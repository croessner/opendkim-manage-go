package dnsupdate

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// TestParseDKIMContentAcceptsCompositeRecords proves the strict rotation
// parser accepts the composite key record without h= and rejects any hash.
func TestParseDKIMContentAcceptsCompositeRecords(t *testing.T) {
	public := bytes.Repeat([]byte{0x5a}, dkim2model.CompositePublicKeyBytes)
	content, err := dkim2model.DNSKeyRecord(dkim2model.AlgorithmMLDSA44Ed25519SHA512, public)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, decoded, err := parseDKIMContent(content)
	if err != nil || algorithm != dkim2model.AlgorithmMLDSA44Ed25519SHA512 || !bytes.Equal(decoded, public) {
		t.Fatalf("parseDKIMContent(composite) algorithm=%q error=%v", algorithm, err)
	}
	encoded := base64.StdEncoding.EncodeToString(public)
	for _, bad := range []string{
		"v=DKIM1; k=mldsa44-ed25519-sha512; h=sha256; p=" + encoded,
		"v=DKIM1; k=mldsa44-ed25519-sha512; h=sha512; p=" + encoded,
		"v=DKIM1; k=MLDSA44-ED25519-SHA512; p=" + encoded,
		"v=DKIM1; p=" + encoded,
	} {
		if _, _, err := parseDKIMContent(bad); err == nil {
			t.Fatalf("parseDKIMContent(%q) accepted", bad[:40])
		}
	}
	if !matchingDKIMContent(content, content) {
		t.Fatal("identical composite records do not match")
	}
}
