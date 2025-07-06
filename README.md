# smtpdump

SMTP server that dumps incoming messages to a directory or other store.

I use this primarily for debugging mail filters/firewalls without the need to set up a full-fledged destination mail server.  Smtpdump also makes debugging the SMTP client-server conversation a breeze.

smtpdump+ can be used as server for multiple email accounts on a VPS or Raspberry Pi.  
Incomming emails will be stores in each users home directory under Mail/inbox.
