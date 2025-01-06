package main

import (
	"time"

	"github.com/emersion/go-smtp"
)

func main() {
	s := smtp.NewServer(nil)

	s.Domain = "localhost" // TODO set correct domain from some config
	s.WriteTimeout = 10 * time.Second
	s.ReadTimeout = 10 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 1
	s.AllowInsecureAuth = false

	// TODO set TLS config s.TLSConfig

	if err := s.ListenAndServeTLS(); err != nil {
		// Show error
	}
}
