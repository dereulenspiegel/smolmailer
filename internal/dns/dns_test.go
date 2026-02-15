package dns

import (
	"math"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func replaceResolveFunc(t *testing.T, newResolve func(string, uint16) ([]dns.RR, error)) {
	t.Cleanup(func() {
		resolve = defaultResolve
	})
	resolve = newResolve
}

func TestVerifyRSADKIMRecord(t *testing.T) {
	expectedRecord := "v=DKIM1;k=rsa;h=sha256;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjYxlWHn3QaeDohpxWCivZyttc7iSx2UzPIoBeFlLX5SahWscfVRP09N/LI8zqoK8vDdpByJ2IEWnQgOTaZ8fHBO4yMy39i2DWBJP300Tb4iWq6NgfBRyHe+w/+BEXS8PioBUfFUvuBTm50R80G6p0jZEntSZrl83VBq8dMW1rn6oz62cdKMaSMb7nYAlwu9CfzAXuIO0NkRnqf2I3vJKT6xf8h6QR9ooOzKnTVdY3H2vg2wVUBz7ow8BoKCw9O/XvtnXmoaGHRNHC8SPllp46l5/2ohoEuo4hdLCUdRVG2om2PK18bdLoJkQQfyaQQGaIVqpzF5wbSUVsiSb+Th+5QIDAQAB"
	replaceResolveFunc(t, func(domain string, recordType uint16) ([]dns.RR, error) {
		return []dns.RR{
			&dns.TXT{
				Txt: []string{expectedRecord},
			},
		}, nil
	})
	result, err := VerifyDKIMRecords("foo", expectedRecord)
	require.NoError(t, err)
	assert.True(t, result.Success())

	replaceResolveFunc(t, func(s string, u uint16) ([]dns.RR, error) {
		recordParts := []string{}
		for i := 0; i < len(expectedRecord); i += 254 {
			maxIndex := int(math.Min(float64(i+254), float64(len(expectedRecord))))
			recordParts = append(recordParts, expectedRecord[i:maxIndex])
		}
		return []dns.RR{
			&dns.TXT{
				Txt: recordParts,
			},
		}, nil
	})

	result, err = VerifyDKIMRecords("foo", expectedRecord)
	require.NoError(t, err)
	assert.True(t, result.Success())

	replaceResolveFunc(t, func(s string, u uint16) ([]dns.RR, error) {
		return []dns.RR{
			&dns.TXT{
				Txt: []string{"baz"},
			},
		}, nil
	})
	result, err = VerifyDKIMRecords("foo", expectedRecord)
	require.NoError(t, err)
	assert.False(t, result.Success())
	assert.Len(t, result.Create, 1)
}
