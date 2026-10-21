package dkim2model

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// lampsCompositeVector is the subset of the LAMPS known-answer vector used here.
type lampsCompositeVector struct {
	PublicKey  string `json:"pk"`
	PrivatePK8 string `json:"sk_pkcs8"`
}

// TestCompositeKeyPairMatchesLAMPSKnownAnswer proves the PKCS#8 decoding and
// public-key derivation reproduce the LAMPS id-MLDSA44-Ed25519-SHA512 vector.
func TestCompositeKeyPairMatchesLAMPSKnownAnswer(t *testing.T) {
	raw, err := os.ReadFile("testdata/lamps/lamps-mldsa44-ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector lampsCompositeVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(vector.PublicKey)
	if err != nil || len(public) != CompositePublicKeyBytes {
		t.Fatalf("vector public key length = %d, error = %v", len(public), err)
	}
	private, err := base64.StdEncoding.DecodeString(vector.PrivatePK8)
	if err != nil {
		t.Fatal(err)
	}
	spki := append(bytes.Clone(compositeSPKIPrefix), public...)
	pair, err := NewKeyPair(AlgorithmMLDSA44Ed25519SHA512, private, spki)
	if err != nil {
		t.Fatalf("NewKeyPair(LAMPS vector) error = %v", err)
	}
	defer func() { _ = pair.Close() }()
	if !bytes.Equal(pair.DNSPublicKeyBytes(), public) {
		t.Fatal("derived DNS public key differs from the vector")
	}
	dns, err := canonicalDNSPublicBytes(AlgorithmMLDSA44Ed25519SHA512, spki)
	if err != nil || !bytes.Equal(dns, public) {
		t.Fatalf("canonicalDNSPublicBytes() error = %v", err)
	}
	other := bytes.Clone(public)
	other[len(other)-1] ^= 0x01
	if _, err := NewKeyPair(AlgorithmMLDSA44Ed25519SHA512, private, append(bytes.Clone(compositeSPKIPrefix), other...)); err == nil {
		t.Fatal("NewKeyPair accepted a public key the seeds do not derive")
	}
}

// TestCompositeKeyPairGeneratesAndRejectsMalformedEncodings proves generation,
// the exact encodings, and fail-closed rejection of malformed input.
func TestCompositeKeyPairGeneratesAndRejectsMalformedEncodings(t *testing.T) {
	pair, err := GenerateKeyPair(AlgorithmMLDSA44Ed25519SHA512, 0, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair(composite) error = %v", err)
	}
	defer func() { _ = pair.Close() }()
	private := pair.PrivatePKCS8DER()
	public := pair.PublicSPKIDER()
	if len(private) != len(compositePKCS8Prefix)+64 || !bytes.HasPrefix(private, compositePKCS8Prefix) ||
		len(public) != len(compositeSPKIPrefix)+CompositePublicKeyBytes || !bytes.HasPrefix(public, compositeSPKIPrefix) ||
		len(pair.DNSPublicKeyBytes()) != CompositePublicKeyBytes {
		t.Fatal("generated composite encodings have the wrong shape")
	}
	for _, test := range []struct {
		name      string
		algorithm Algorithm
		private   []byte
		public    []byte
	}{
		{"trailing private byte", AlgorithmMLDSA44Ed25519SHA512, append(bytes.Clone(private), 0), public},
		{"trailing public byte", AlgorithmMLDSA44Ed25519SHA512, private, append(bytes.Clone(public), 0)},
		{"composite as ed25519", AlgorithmEd25519SHA256, private, public},
		{"zero seeds", AlgorithmMLDSA44Ed25519SHA512, append(bytes.Clone(compositePKCS8Prefix), make([]byte, 64)...), public},
	} {
		if _, err := NewKeyPair(test.algorithm, test.private, test.public); err == nil {
			t.Fatalf("%s accepted", test.name)
		}
	}
	if _, err := GenerateCompositeKeyPair(bytes.NewReader(make([]byte, 63))); err == nil {
		t.Fatal("short entropy accepted")
	}
	ed, err := GenerateKeyPair(AlgorithmEd25519SHA256, 0, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ed.Close() }()
	if _, err := canonicalDNSPublicBytes(AlgorithmMLDSA44Ed25519SHA512, ed.PublicSPKIDER()); err == nil {
		t.Fatal("Ed25519 SPKI accepted as composite")
	}
}

// TestAlgorithmOrderAndDNSRecordOwnership proves the canonical order, the
// credential bound, and the single DNS key-record vocabulary.
func TestAlgorithmOrderAndDNSRecordOwnership(t *testing.T) {
	want := []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmMLDSA44Ed25519SHA512}
	order := SigningAlgorithms()
	if !slices.Equal(order, want) || MaxCredentialsPerProfile != 3 {
		t.Fatalf("SigningAlgorithms() = %v", order)
	}
	order[0] = AlgorithmMLDSA44Ed25519SHA512
	if !slices.Equal(SigningAlgorithms(), want) {
		t.Fatal("caller mutation changed the canonical order")
	}
	shuffled := []Algorithm{AlgorithmMLDSA44Ed25519SHA512, AlgorithmRSASHA256, AlgorithmEd25519SHA256}
	slices.SortFunc(shuffled, CompareAlgorithms)
	if !slices.Equal(shuffled, want) || CompareAlgorithms("unknown", AlgorithmMLDSA44Ed25519SHA512) <= 0 {
		t.Fatalf("CompareAlgorithms order = %v", shuffled)
	}
	record, err := DNSKeyRecord(AlgorithmMLDSA44Ed25519SHA512, []byte{1, 2, 3})
	if err != nil || record != "v=DKIM1; k=mldsa44-ed25519-sha512; p=AQID" {
		t.Fatalf("composite record = %q, %v", record, err)
	}
	record, err = DNSKeyRecord(AlgorithmEd25519SHA256, []byte{1, 2, 3})
	if err != nil || record != "v=DKIM1; k=ed25519; h=sha256; p=AQID" {
		t.Fatalf("ed25519 record = %q, %v", record, err)
	}
	for keyType, algorithm := range map[string]Algorithm{
		"rsa": AlgorithmRSASHA256, "ed25519": AlgorithmEd25519SHA256,
		"mldsa44-ed25519-sha512": AlgorithmMLDSA44Ed25519SHA512,
	} {
		if got, ok := AlgorithmForDNSKeyType(keyType, true); !ok || got != algorithm {
			t.Fatalf("AlgorithmForDNSKeyType(%q) = %q", keyType, got)
		}
	}
	if _, ok := AlgorithmForDNSKeyType("MLDSA44-ED25519-SHA512", true); ok {
		t.Fatal("non-canonical key type accepted")
	}
	if !AlgorithmMLDSA44Ed25519SHA512.DNSHashAllowed("", false) ||
		AlgorithmMLDSA44Ed25519SHA512.DNSHashAllowed("sha256", true) ||
		!AlgorithmRSASHA256.DNSHashAllowed("sha256", true) {
		t.Fatal("DNSHashAllowed vocabulary drifted")
	}
	if _, err := DNSKeyRecord("unknown", []byte{1}); err == nil || strings.Contains(record, "unknown") {
		t.Fatal("unknown algorithm rendered")
	}
}
