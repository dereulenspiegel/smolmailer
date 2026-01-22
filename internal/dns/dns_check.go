package dns

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/asggo/spf"
	"github.com/dereulenspiegel/smolmailer/internal/config"
	"github.com/dereulenspiegel/smolmailer/internal/utils"
	"github.com/miekg/dns"
)

var (
	ErrNoDKIMRecord     = errors.New("no dkim record found")
	ErrNoSPFRecord      = errors.New("no spf record found")
	ErrInvalidSPFRecord = errors.New("invalid SPF record")
	ErrRecordNotFound   = errors.New("record not found")
)

type ResourceRecord struct {
	Type   string
	Domain string
	Record string
}

func (rr ResourceRecord) String() string {
	return fmt.Sprintf("Type %s Domain %s Value %s", rr.Type, rr.Domain, rr.Record)
}

type VerificationResult struct {
	Create []ResourceRecord
	Delete []ResourceRecord
	Update []ResourceRecord
}

func (v *VerificationResult) Success() bool {
	return len(v.Create) == 0 && len(v.Delete) == 0 && len(v.Update) == 0
}

func (v *VerificationResult) Merge(other *VerificationResult) *VerificationResult {
	return &VerificationResult{
		Create: append(v.Create, other.Create...),
		Update: append(v.Update, other.Update...),
		Delete: append(v.Delete, other.Delete...),
	}
}

func newVerificarionResult() *VerificationResult {
	return &VerificationResult{
		Create: []ResourceRecord{},
		Delete: []ResourceRecord{},
		Update: []ResourceRecord{},
	}
}

func VerifyValidDKIMRecords(domain string, dkimConfig *config.DkimOpts) (*VerificationResult, error) {
	ed25519PemString, err := dkimConfig.PrivateKeys.Ed25519.GetKey()
	if err != nil {
		return nil, err
	}
	dkimPrivKey, err := utils.ParseDkimKey(ed25519PemString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ed25519 private key: %w", err)
	}
	var ed25519Result *VerificationResult
	if ed25519Result, err = verifyDkimRecordForKey(dkimConfig.Selector, domain, dkimPrivKey); err != nil {
		return nil, err
	}

	rsaPemString, err := dkimConfig.PrivateKeys.RSA.GetKey()
	if err != nil {
		return nil, err
	}
	dkimPrivKey, err = utils.ParseDkimKey(rsaPemString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	var rsaResult *VerificationResult
	if rsaResult, err = verifyDkimRecordForKey(dkimConfig.Selector, domain, dkimPrivKey); err != nil {
		return nil, err
	}
	return ed25519Result.Merge(rsaResult), nil
}

func verifyDkimRecordForKey(selector, domain string, privKey crypto.PrivateKey) (*VerificationResult, error) {

	dkimRecordContent, err := utils.DkimTxtRecordContent(privKey)
	if err != nil {
		return nil, err
	}
	dkimRecordDomain := utils.DkimDomain(selector, domain)
	return VerifyDKIMRecords(dkimRecordDomain, dkimRecordContent)
}

func VerifyDKIMRecords(domain, value string) (*VerificationResult, error) {
	result := newVerificarionResult()
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
		return nil, fmt.Errorf("failed to contact DNS server: %w", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		result.Create = append(result.Create, ResourceRecord{
			Type:   "TXT",
			Domain: domain,
			Record: value,
		})
		return result, nil
	}

	answer, err := resolve(domain, dns.TypeTXT)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			result.Create = append(result.Create, ResourceRecord{
				Type:   "TXT",
				Domain: domain,
				Record: value,
			})
			return result, nil
		}
		return nil, err
	}

	validFound := false
	for _, a := range answer {
		if rrTxt, ok := a.(*dns.TXT); ok {
			for _, txtVal := range rrTxt.Txt {
				if txtVal != value {
					result.Delete = append(result.Delete, ResourceRecord{
						Type:   "TXT",
						Domain: domain,
						Record: txtVal,
					})
				} else {
					validFound = true
				}
			}
		}
	}
	if !validFound {
		result.Create = append(result.Create, ResourceRecord{
			Type:   "TXT",
			Domain: domain,
			Record: value,
		})
	}
	return result, nil
}

const defaultDNSQueryCount = 3

func VerifySPFRecord(mailDomain, tlsdomain, sendAddr string) error {
	answer, err := resolve(mailDomain, dns.TypeTXT)
	if err != nil {
		return err
	}

	for _, a := range answer {
		if rrTxt, ok := a.(*dns.TXT); ok {
			for _, txtVal := range rrTxt.Txt {
				if strings.HasPrefix(txtVal, "v=") {
					spfValue, err := spf.NewSPF(mailDomain, txtVal, defaultDNSQueryCount)
					if err != nil {
						continue
					}
					spfResult := spfValue.Test(sendAddr)
					switch spfResult {
					case spf.Pass, spf.Neutral:
						return nil
					case spf.Fail, spf.SoftFail, spf.None, spf.TempError, spf.PermError:
						return ErrInvalidSPFRecord
					default:
						return errors.New("Additional spf check result, this should not be reachable")
					}
				}
			}
		}
	}
	return ErrNoSPFRecord
}

func resolve(rrDomain string, rrType uint16) ([]dns.RR, error) {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	m := new(dns.Msg)
	if !strings.HasSuffix(rrDomain, ".") {
		rrDomain = rrDomain + "."
	}
	m.SetQuestion(rrDomain, rrType)

	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to contact DNS server: %w", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, ErrRecordNotFound
	}
	return r.Answer, nil
}
