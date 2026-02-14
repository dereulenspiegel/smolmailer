package dns

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

	mainResult := &VerificationResult{}

	for _, signingConfig := range dkimConfig.Signer {
		privKeyPem, err := signingConfig.PrivateKey.GetKey()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve private key: %w", err)
		}

		dkimPrivKey, err := utils.ParseDkimKey(privKeyPem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DKIM private key: %w", err)
		}
		dkimResult, err := verifyDkimRecordForKey(signingConfig.Selector, domain, dkimPrivKey)
		if err != nil {
			return nil, err
		}
		mainResult = mainResult.Merge(dkimResult)
	}

	return mainResult, nil
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

	compoundResource := ""
	for _, a := range answer {
		if rrTxt, ok := a.(*dns.TXT); ok {
			for _, txtVal := range rrTxt.Txt {
				compoundResource += txtVal
			}
		}
	}
	if compoundResource != value {
		result.Create = append(result.Update, ResourceRecord{
			Type:   "TXT",
			Domain: domain,
			Record: value,
		})
	}
	return result, nil
}

const defaultDNSQueryCount = 3

func VerifySPFRecord(mailDomain, tlsdomain, sendAddr string) (*VerificationResult, error) {
	answer, err := resolve(mailDomain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	correctSPFFound := false
	result := &VerificationResult{}

	for _, a := range answer {
		if rrTxt, ok := a.(*dns.TXT); ok {
			for _, txtVal := range rrTxt.Txt {
				if strings.HasPrefix(txtVal, "v=spf1") {
					spfValue, err := spf.NewSPF(mailDomain, txtVal, defaultDNSQueryCount)
					if err != nil {
						result.Delete = append(result.Delete, ResourceRecord{
							Type:   "TXT",
							Domain: mailDomain,
							Record: txtVal,
						})
						continue
					}
					spfResult := spfValue.Test(sendAddr)
					switch spfResult {
					case spf.Pass, spf.Neutral:
						correctSPFFound = true
						continue
					case spf.Fail, spf.SoftFail, spf.None, spf.TempError, spf.PermError:
						result.Delete = append(result.Delete, ResourceRecord{
							Type:   "TXT",
							Domain: mailDomain,
							Record: txtVal,
						})
						continue
					default:
						return nil, errors.New("additional spf check result, this should not be reachable")
					}
				}
			}
		}
	}
	senderIP, err := netip.ParseAddr(sendAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sendAddr into IP: %w", err)
	}
	ipTypeStr := "ip4"
	if senderIP.Is6() {
		ipTypeStr = "ip6"
	}
	if !correctSPFFound {
		result.Create = append(result.Create, ResourceRecord{
			Type:   "TXT",
			Domain: mailDomain,
			Record: fmt.Sprintf("v=spf1 %s:%s -all", ipTypeStr, senderIP.String()),
		})
	}
	return result, nil
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
