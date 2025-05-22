package main

import (
	"bytes"
	"crypto/tls"
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
	ReadTimeout  = 60 * time.Second
	WriteTimeout = 60 * time.Second
	InputLimit   = 1024 * 1024
)

var (
	addr      = flag.String("addr", "127.0.0.1:2525", "Listen address:port")
	cert      = flag.String("cert", "", "PEM-encoded certificate")
	colorize  = flag.Bool("color", true, "colorize debug output")
	discard   = flag.Bool("discard", false, "discard incoming messages")
	extension = flag.String("extension", "eml", "Saved file extension")
	output    = flag.String("output", "", "Output directory (default to current directory)")
	minTLS11  = flag.Bool("tls11", false, "accept TLSv1.1 as a minimum")
	minTLS12  = flag.Bool("tls12", false, "accept TLSv1.2 as a minimum")
	minTLS13  = flag.Bool("tls13", false, "accept TLSv1.3 as a minimum")
	pkey      = flag.String("key", "", "PEM-encoded private key")
	verbose   = flag.Bool("verbose", false, "verbose output")
	readPrintf  = color.New(color.FgGreen).Printf
	writePrintf = color.New(color.FgCyan).Printf
	hostname string
)

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

	var handler smtpd.Handler
	if *discard {
		handler = discardHandler(*verbose)
	} else {
		handler = outputHandler(*output, *extension, *verbose)
	}

	srv := &smtpd.Server{
            Addr:        *addr,
            Appname:     "SMTPDump",
            AuthHandler: authHandler,
            Handler:     handler,
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

func discardHandler(verbose bool) func(remoteAddr net.Addr, from string, to []string, data []byte) error {
    return func(origin net.Addr, from string, to []string, data []byte) error {
        if verbose {
            msg, err := mail.ReadMessage(bytes.NewReader(data))
            if err != nil {
                log.Println(err)
                return err
            }
            subject := msg.Header.Get("Subject")
            log.Printf("Received mail from %q with subject %q\n", from, subject)
        }
        return nil
    }
}

func outputHandler(output, ext string, verbose bool) func(remoteAddr net.Addr, from string, to []string, data []byte) error {
    return func(origin net.Addr, from string, to []string, data []byte) error {
        fileName, err := generateFileName(output, from, data)
        if err != nil {
            log.Printf("Error generating filename: %v\n", err)
            return err
        }

        f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
        if err != nil {
            log.Printf("Error creating file: %v\n", err)
            return err
        }
        defer f.Close()

        _, err = io.Copy(f, bytes.NewReader(data))
        if err != nil {
            log.Printf("Error writing file: %v\n", err)
            return err
        }

        if verbose {
            log.Printf("Wrote message to %q\n", fileName)
        }
        return nil
    }
}

func generateFileName(dir, from string, data []byte) (string, error) {
	msg, _ := mail.ReadMessage(bytes.NewReader(data))
	subject := "no_subject"
	if msg != nil && msg.Header.Get("Subject") != "" {
		subject = sanitizeFileName(msg.Header.Get("Subject"))
	}
	
	timestamp := time.Now().Format("20060102_150405")
	fromAddr := sanitizeFileName(from)
	
	fileName := fmt.Sprintf("%s_%s_%s.eml", timestamp, fromAddr, subject)
	return filepath.Join(dir, fileName), nil
}

func sanitizeFileName(input string) string {
	invalid := []string{"/", "\\", "?", "%", "*", ":", "|", "\"", "<", ">", " "}
	result := input
	for _, char := range invalid {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
}

func rcptHandler(_ net.Addr, from string, to string) bool {
	log.Printf("[RCPT] %q => %q\n", from, to)
	return true
}
