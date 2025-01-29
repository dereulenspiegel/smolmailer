package smolmailer

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

var ErrNoDKIMRecord = errors.New("no dkim record found")

func VerifyDKIMRecords(domain, value string) error {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	m := new(dns.Msg)
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	m.SetQuestion(domain, dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if err != nil {
		return fmt.Errorf("failed to contact DNS server: %w", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return ErrNoDKIMRecord
	}

	for _, a := range r.Answer {
		if rrTxt, ok := a.(*dns.TXT); ok {
			for _, txtVal := range rrTxt.Txt {
				if txtVal == value {
					return nil
				}
			}
		}
	}
	return ErrNoDKIMRecord
}
