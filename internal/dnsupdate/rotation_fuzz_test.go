package dnsupdate

import (
	"testing"

	"github.com/miekg/dns"
)

func FuzzDKIM2DNSContentParser(f *testing.F) {
	for _, seed := range []string{
		testDKIMRecord,
		"v=DKIM1; k=rsa; h=sha256; p=AQIDBA==",
		"v=DKIM1; k=ed25519; h=sha256; p=",
		"v=DKIM1; k=rsa; h=sha1; p=AQID",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > 8192 {
			t.Skip()
		}
		_ = validateDKIMContent(content)
	})
}

func FuzzDKIM2DNSResponseParser(f *testing.F) {
	expected := ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}
	valid := new(dns.Msg)
	valid.SetQuestion(expected.Owner, dns.TypeTXT)
	valid.Response = true
	valid.Authoritative = true
	valid.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: expected.Owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{expected.Content},
	}}
	wire, err := valid.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		message := new(dns.Msg)
		if err := message.Unpack(input); err != nil {
			return
		}
		_, _ = classifyProofResponse(message, expected, ProofAuthoritative)
		_, _ = classifyProofResponse(message, expected, ProofRecursive)
		_, _ = classifyPresenceResponse(message, expected)
	})
}
