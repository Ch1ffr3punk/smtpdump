package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mhale/smtpd"
	"golang.org/x/time/rate"
)

const (
	ReadTimeout          = 60 * time.Second
	WriteTimeout         = 60 * time.Second
	InputLimit           = 1024 * 1024
	MailQueueBufferSize  = 100 // How many mails can be buffered
	FileSaverWorkerCount = 5   // How many concurrent goroutines save files
)

var (
	addr        = flag.String("addr", "127.0.0.1:2525", "Listen address:port")
	cert        = flag.String("cert", "", "PEM-encoded certificate")
	colorize    = flag.Bool("color", true, "colorize debug output")
	discard     = flag.Bool("discard", false, "discard incoming messages")
	extension   = flag.String("extension", "eml", "Saved file extension")
	output      = flag.String("output", "", "Output directory (default to current directory)")
	minTLS11    = flag.Bool("tls11", false, "accept TLSv1.1 as a minimum")
	minTLS12    = flag.Bool("tls12", false, "accept TLSv1.2 as a minimum")
	minTLS13    = flag.Bool("tls13", false, "accept TLSv1.3 as a minimum")
	pkey        = flag.String("key", "", "PEM-encoded private key")
	verbose     = flag.Bool("verbose", false, "verbose output")
	readPrintf  = color.New(color.FgGreen).Printf
	writePrintf = color.New(color.FgCyan).Printf
	hostname    string

	// Global channel for queuing emails to be saved
	mailSaverQueue chan *mailDataToSave
)

// mailDataToSave struct holds necessary data for saving an email
type mailDataToSave struct {
	RemoteAddr net.Addr
	From       string
	To         []string
	Data       []byte
	ReceivedAt time.Time
	RetryCount int
}

func init() {
	hn, err := os.Hostname()
	if err != nil {
		log.Fatalln(err)
	}
	flag.StringVar(&hostname, "hostname", hn, "Server host name")
	flag.BoolVar(&smtpd.Debug, "debug", false, "debug output")
}

func main() {
	flag.Parse()
	if hostname == "" {
		log.Fatalln("Hostname cannot be empty")
	}
	if smtpd.Debug {
		*verbose = true
		if !*colorize {
			readPrintf = fmt.Printf
			writePrintf = fmt.Printf
		}
	}

	var err error
	if *output == "" {
		*output, err = os.Getwd()
		if err != nil {
			log.Fatalln(err)
		}
	}
	_, err = os.Stat(*output)
	if err != nil {
		log.Fatalln(err)
	}

	// Initialize the mail queue as a bidirectional channel
	mailSaverQueue = make(chan *mailDataToSave, MailQueueBufferSize)

	// Start the background workers for saving emails
	startFileSaverWorkers(mailSaverQueue, FileSaverWorkerCount, *output, *extension, *verbose)

	var handler smtpd.Handler
	if *discard {
		handler = discardHandler(*verbose)
	} else {
		// Use the new queuing handler
		handler = queuingOutputHandler(mailSaverQueue, *verbose)
	}

	srv := &smtpd.Server{
		Addr:        *addr,
		Appname:     "SMTPDump",
		AuthHandler: authHandler,
		Handler:     handler, // This is now the queuing handler
		MaxSize:     InputLimit,
		LogRead: func(_, _, line string) {
			line = strings.Replace(line, "\n", "\n  ", -1)
			_, _ = readPrintf("  %s\n", line)
		},
		LogWrite: func(_, _, line string) {
			line = strings.Replace(line, "\n", "\n  ", -1)
			_, _ = writePrintf("  %s\n", line)
		},
		HandlerRcpt: rcptHandler,
	}

	if *cert != "" && *pkey != "" {
		err = srv.ConfigureTLS(*cert, *pkey)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Enabled TLS support")
		switch {
		case *minTLS13:
			srv.TLSConfig.MinVersion = tls.VersionTLS13
			log.Println("Minimum TLSv1.3 accepted")
		case *minTLS12:
			srv.TLSConfig.MinVersion = tls.VersionTLS12
			log.Println("Minimum TLSv1.2 accepted")
		case *minTLS11:
			srv.TLSConfig.MinVersion = tls.VersionTLS11
			log.Println("Minimum TLSv1.1 accepted")
		}
	}

	rateLimitedSrv := newRateLimitedServer(srv)

	if *verbose {
		log.Printf("Listening on %q ...\n", *addr)
	}
	log.Fatalln(rateLimitedSrv.ListenAndServe())
}

type rateLimitedServer struct {
	*smtpd.Server
	limiter *rate.Limiter
}

func (s *rateLimitedServer) ListenAndServe() error {
	return s.Server.ListenAndServe()
}

func newRateLimitedServer(srv *smtpd.Server) *rateLimitedServer {
	return &rateLimitedServer{
		Server:  srv,
		limiter: rate.NewLimiter(rate.Every(time.Second), 5),
	}
}

func authHandler(_ net.Addr, _ string, username []byte, password []byte, _ []byte) (bool, error) {
	log.Printf("[AUTH] User: %q; Password: %q\n", username, password)
	return true, nil
}

func discardHandler(verbose bool) smtpd.Handler {
	return func(origin net.Addr, from string, to []string, data []byte) error {
		if verbose {
			msg, err := mail.ReadMessage(bytes.NewReader(data))
			if err != nil {
				log.Println(err)
				return err
			}
			subject := msg.Header.Get("Subject")
			log.Printf("Received mail from %q to %q with subject %q (Discarded)\n", from, to, subject)
		}
		return nil
	}
}

// queuingOutputHandler queues the email for asynchronous saving
// It now receives a send-only channel `chan<-` which is appropriate
// for the handler's role of only sending data *into* the queue.
func queuingOutputHandler(queue chan<- *mailDataToSave, verbose bool) smtpd.Handler {
	return func(origin net.Addr, from string, to []string, data []byte) error {
		mailToSave := &mailDataToSave{
			RemoteAddr: origin,
			From:       from,
			To:         to,
			Data:       data,
			ReceivedAt: time.Now(),
			RetryCount: 0,
		}

		select {
		case queue <- mailToSave:
			if verbose {
				msg, err := mail.ReadMessage(bytes.NewReader(data))
				subject := "no_subject"
				if err == nil {
					subject = msg.Header.Get("Subject")
				}
				log.Printf("INFO: Mail from %q to %q with subject %q queued for saving.\n", from, to, subject)
			}
			return nil // Return success immediately to the client
		default:
			log.Printf("WARNING: Mail queue is full, could not queue mail from %q to %q. Consider increasing MailQueueBufferSize.\n", from, to)
			// Returning a generic error here as smtpd.Error is not available.
			// This will likely result in a 554 Transaction failed response from the smtpd library.
			return errors.New("Server queue full, please try again later (internal error)")
		}
	}
}

// saveMailToFile performs the actual file saving operation
func saveMailToFile(data *mailDataToSave, outputDir, ext string, verbose bool) error {
	fileName, err := generateFileName(outputDir, data.From, data.Data, ext)
	if err != nil {
		log.Printf("Error generating filename for mail from %q: %v\n", data.From, err)
		return err
	}

	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Printf("Error creating file %q: %v\n", fileName, err)
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, bytes.NewReader(data.Data))
	if err != nil {
		log.Printf("Error writing file %q: %v\n", fileName, err)
		return err
	}

	if verbose {
		log.Printf("Successfully saved message from %q to %q\n", data.From, fileName)
	}
	return nil
}

// startFileSaverWorkers initializes background goroutines to save emails from the queue.
// The 'queue' parameter is a bidirectional channel 'chan *mailDataToSave'
// to allow re-queueing messages if saving fails.
func startFileSaverWorkers(queue chan *mailDataToSave, workerCount int, outputDir, ext string, verbose bool) {
	for i := 0; i < workerCount; i++ {
		go func(workerID int) {
			log.Printf("File Saver Worker %d started.\n", workerID)
			for mailToSave := range queue {
				err := saveMailToFile(mailToSave, outputDir, ext, verbose)
				if err != nil {
					log.Printf("File Saver Worker %d: Failed to save mail from %q (Retry %d): %v\n", workerID, mailToSave.From, mailToSave.RetryCount, err)
					
					if mailToSave.RetryCount < 3 { // Example: Max 3 retries
						mailToSave.RetryCount++
						// Re-queue with a delay. Use a new goroutine to avoid blocking the worker.
						go func(m *mailDataToSave) {
							time.Sleep(5 * time.Second * time.Duration(m.RetryCount))
							select {
							case queue <- m: // Now able to send back into the queue
								log.Printf("File Saver Worker %d: Re-queued mail from %q for retry %d.\n", workerID, m.From, m.RetryCount)
							default:
								log.Printf("File Saver Worker %d: Failed to re-queue mail from %q, queue full. Dropped after %d retries.\n", workerID, m.From, m.RetryCount-1)
							}
						}(mailToSave)
					} else {
						log.Printf("File Saver Worker %d: Mail from %q permanently failed to save after %d retries.\n", workerID, mailToSave.From, mailToSave.RetryCount)
					}
				} else {
					log.Printf("File Saver Worker %d: Successfully processed mail from %q.\n", workerID, mailToSave.From)
				}
			}
			log.Printf("File Saver Worker %d stopped.\n", workerID)
		}(i)
	}
}

func generateFileName(dir, from string, data []byte, ext string) (string, error) {
	msg, _ := mail.ReadMessage(bytes.NewReader(data))
	subject := "no_subject"
	if msg != nil && msg.Header.Get("Subject") != "" {
		subject = sanitizeFileName(msg.Header.Get("Subject"))
	}
	
	timestamp := time.Now().Format("20060102_150405")
	fromAddr := sanitizeFileName(from)
	
	fileName := fmt.Sprintf("%s_%s_%s.%s", timestamp, fromAddr, subject, ext)
	return filepath.Join(dir, fileName), nil
}

func sanitizeFileName(input string) string {
	invalid := []string{"/", "\\", "?", "%", "*", ":", "|", "\"", "<", ">", " "}
	result := input
	for _, char := range invalid {
		result = strings.ReplaceAll(result, char, "_")
	}
	result = strings.ReplaceAll(result, ".", "_")
	return result
}

func rcptHandler(_ net.Addr, from string, to string) bool {
	log.Printf("[RCPT] %q => %q\n", from, to)
	return true
}