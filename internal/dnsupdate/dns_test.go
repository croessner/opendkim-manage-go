package dnsupdate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

func TestMake254(t *testing.T) {
	in := strings.Repeat("a", 600)
	out := Make254(in)
	parts := strings.Split(out, " ")
	if len(parts) < 3 {
		t.Fatalf("expected multiple chunks, got %q", out)
	}
	for _, p := range parts {
		if len(p) > 256 {
			t.Fatalf("chunk too long: %d", len(p))
		}
	}
}

func TestUpsertReplacesOnlyTXTAndInsertsOneLogicalRecord(t *testing.T) {
	content := "v=DKIM1; p=" + strings.Repeat("A", 600)
	msg := buildUpsertMessage("example.org", "selector1", content, "", 300)
	if len(msg.Ns) != 2 {
		t.Fatalf("expected delete plus insert, got %d updates", len(msg.Ns))
	}
	if msg.Ns[0].Header().Rrtype != dns.TypeTXT || msg.Ns[0].Header().Class != dns.ClassANY {
		t.Fatalf("first update is not a TXT RRset removal: %#v", msg.Ns[0])
	}
	txt, ok := msg.Ns[1].(*dns.TXT)
	if !ok {
		t.Fatalf("second update is not TXT: %T", msg.Ns[1])
	}
	if got := strings.Join(txt.Txt, ""); got != content {
		t.Fatalf("TXT chunks changed content")
	}
	for _, chunk := range txt.Txt {
		if len(chunk) > 254 {
			t.Fatalf("TXT chunk too long: %d", len(chunk))
		}
	}
}

func TestRemoveDeletesOnlyTXTRRset(t *testing.T) {
	msg := buildRemoveMessage("example.org", "selector1", "")
	if len(msg.Ns) != 1 {
		t.Fatalf("expected one update, got %d", len(msg.Ns))
	}
	if msg.Ns[0].Header().Rrtype != dns.TypeTXT || msg.Ns[0].Header().Class != dns.ClassANY {
		t.Fatalf("unexpected removal: %#v", msg.Ns[0])
	}
}

func TestResolveUpdateTargetUsesParentSOAForSubdomain(t *testing.T) {
	client := &Client{
		cfg: &config.Config{},
		soaLookup: func(zone string) (bool, error) {
			return zone == "example.com", nil
		},
	}

	zone, subdomain, err := client.resolveUpdateTarget("reports.example.com", "")
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	if zone != "example.com" {
		t.Fatalf("unexpected zone: %q", zone)
	}
	if subdomain != "reports" {
		t.Fatalf("unexpected subdomain: %q", subdomain)
	}
}

func TestResolveUpdateTargetKeepsAuthoritativeZone(t *testing.T) {
	client := &Client{
		cfg: &config.Config{},
		soaLookup: func(zone string) (bool, error) {
			return zone == "example.com", nil
		},
	}

	zone, subdomain, err := client.resolveUpdateTarget("example.com", "")
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	if zone != "example.com" {
		t.Fatalf("unexpected zone: %q", zone)
	}
	if subdomain != "" {
		t.Fatalf("unexpected subdomain: %q", subdomain)
	}
}

func TestResolveUpdateTargetPropagatesSOAErrors(t *testing.T) {
	want := "lookup failed"
	client := &Client{
		cfg: &config.Config{},
		soaLookup: func(string) (bool, error) {
			return false, fmt.Errorf("%s", want)
		},
	}
	if _, _, err := client.resolveUpdateTarget("example.org", ""); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected SOA error, got %v", err)
	}
}

func TestValidateUpdateResponseRequiresTSIG(t *testing.T) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	if err := validateUpdateResponse(response, true); err == nil {
		t.Fatal("expected unsigned response to be rejected")
	}
	response.SetTsig("update-key.", dns.HmacSHA256, 300, 0)
	if err := validateUpdateResponse(response, true); err != nil {
		t.Fatalf("signed response rejected: %v", err)
	}
}

func TestValidateUpdateResponseRejectsNilAndFailureRcode(t *testing.T) {
	if err := validateUpdateResponse(nil, false); err == nil {
		t.Fatal("expected nil response error")
	}
	response := new(dns.Msg)
	response.Rcode = dns.RcodeRefused
	if err := validateUpdateResponse(response, false); err == nil {
		t.Fatal("expected failure rcode error")
	}
}
