package dkim2model

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestClosedValuesAndCanonicalNames(t *testing.T) {
	for _, value := range []string{"tenant", "tenant.example-1", "a_b"} {
		if err := ValidateIdentifier(value); err != nil {
			t.Fatalf("ValidateIdentifier(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"", "Upper", "-leading", ".leading", "x/y", strings.Repeat("a", 129)} {
		if err := ValidateIdentifier(value); err == nil {
			t.Fatalf("ValidateIdentifier(%q) unexpectedly succeeded", value)
		}
	}
	for _, value := range []string{"example.test", "selector-1", "a.b-c"} {
		if err := ValidateCanonicalDNSName(value); err != nil {
			t.Fatalf("ValidateCanonicalDNSName(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"Example.test", "bad_name", "-bad.test", "bad-.test", "bad..test", "example.test."} {
		if err := ValidateCanonicalDNSName(value); err == nil {
			t.Fatalf("ValidateCanonicalDNSName(%q) unexpectedly succeeded", value)
		}
	}
	if canonical, err := CanonicalDomain("Example.TEST"); err != nil || canonical != "example.test" {
		t.Fatalf("CanonicalDomain() = %q, %v", canonical, err)
	}
	for _, value := range []string{"rsa-sha256", "ed25519-sha256"} {
		if _, err := ParseAlgorithm(value); err != nil {
			t.Fatalf("ParseAlgorithm(%q) error = %v", value, err)
		}
	}
	if _, err := ParseAlgorithm("RSA-SHA256"); err == nil {
		t.Fatal("ParseAlgorithm accepted a noncanonical value")
	}
	for _, value := range []string{"originator", "ordinary_transit", "next_domain_transit", "delivery_status"} {
		use, err := ParseProfileUse(value)
		if err != nil || !use.Known() {
			t.Fatalf("ParseProfileUse(%q) = %q, %v", value, use, err)
		}
	}
	for _, value := range []ProfileUse{ProfileUseOriginator, ProfileUseOrdinaryTransit, ProfileUseDeliveryStatus} {
		if !value.SupportsNativeKeyCustody() {
			t.Fatalf("profile use %q unexpectedly rejects native key custody", value)
		}
	}
	if ProfileUseNextDomainTransit.SupportsNativeKeyCustody() {
		t.Fatal("next-domain transit unexpectedly accepts native key custody")
	}
}

func TestValidateDomainSelectorRejectsOversizedCompositeOwner(t *testing.T) {
	domain := strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63)
	selector := strings.Repeat("s", 63)
	if ValidateCanonicalDNSName(domain) != nil || ValidateCanonicalDNSName(selector) != nil {
		t.Fatal("test components must be valid independently")
	}
	if err := ValidateDomainSelector(domain, selector); err == nil {
		t.Fatal("ValidateDomainSelector accepted an oversized composite DNS owner")
	}
}

func TestKeyPairEncodingsCloneAndRedaction(t *testing.T) {
	rsaPair, err := GenerateRSAKeyPair(DefaultRSABits, nil)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() error = %v", err)
	}
	defer func() { _ = rsaPair.Close() }()
	rsaPrivate := rsaPair.PrivatePKCS8DER()
	rsaPublic := rsaPair.PublicSPKIDER()
	rsaDNS := rsaPair.DNSPublicKeyBytes()
	privateAny, err := x509.ParsePKCS8PrivateKey(rsaPrivate)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey() error = %v", err)
	}
	private, ok := privateAny.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T", privateAny)
	}
	if !bytes.Equal(rsaDNS, rsaPublic) {
		t.Fatal("RSA DNS bytes are not SubjectPublicKeyInfo DER")
	}
	pkcs1RSA := x509.MarshalPKCS1PublicKey(&private.PublicKey)
	if bytes.Equal(rsaDNS, pkcs1RSA) {
		t.Fatal("RSA DNS bytes unexpectedly use PKCS#1 RSAPublicKey DER")
	}
	if !DNSPublicKeyMatchesSPKI(AlgorithmRSASHA256, rsaPublic, rsaDNS) ||
		!DNSPublicKeyMatchesSPKI(AlgorithmRSASHA256, rsaPublic, pkcs1RSA) {
		t.Fatal("RSA DNS compatibility does not accept both canonical encodings")
	}
	if DNSPublicKeyMatchesSPKI(AlgorithmRSASHA256, rsaPublic, append(bytes.Clone(pkcs1RSA), 0)) {
		t.Fatal("RSA DNS compatibility accepted noncanonical PKCS#1 DER")
	}

	edPair, err := GenerateEd25519KeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	defer func() { _ = edPair.Close() }()
	publicAny, err := x509.ParsePKIXPublicKey(edPair.PublicSPKIDER())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	edPublic, ok := publicAny.(ed25519.PublicKey)
	if !ok || !bytes.Equal(edPair.DNSPublicKeyBytes(), edPublic) {
		t.Fatal("Ed25519 DNS bytes are not the raw public key")
	}
	if bytes.Equal(edPair.DNSPublicKeyBytes(), edPair.PublicSPKIDER()) {
		t.Fatal("Ed25519 DNS and SPKI encodings were conflated")
	}
	if !DNSPublicKeyMatchesSPKI(AlgorithmEd25519SHA256, edPair.PublicSPKIDER(), edPublic) ||
		DNSPublicKeyMatchesSPKI(AlgorithmEd25519SHA256, edPair.PublicSPKIDER(), edPair.PublicSPKIDER()) {
		t.Fatal("Ed25519 DNS compatibility accepted a non-raw encoding")
	}

	clone, err := rsaPair.Clone()
	if err != nil {
		t.Fatalf("Clone() error = %v", err)
	}
	defer func() { _ = clone.Close() }()
	rsaPrivate[0] ^= 0xff
	rsaPublic[0] ^= 0xff
	rsaDNS[0] ^= 0xff
	if !rsaPair.Equivalent(clone) {
		t.Fatal("caller mutation changed retained key material")
	}
	marker := fmt.Sprintf("%x", clone.PrivatePKCS8DER()[:24])
	encoded, err := json.Marshal(clone)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, output := range []string{fmt.Sprint(clone), fmt.Sprintf("%#v", clone), string(encoded)} {
		if output == "" || strings.Contains(output, marker) {
			t.Fatal("formatting exposed private key material")
		}
	}
}

func TestNewKeyPairRejectsMismatchAndNoncanonicalDER(t *testing.T) {
	rsaPair, err := GenerateRSAKeyPair(DefaultRSABits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rsaPair.Close() }()
	edPair, err := GenerateEd25519KeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = edPair.Close() }()

	if pair, err := NewKeyPair(AlgorithmRSASHA256, rsaPair.PrivatePKCS8DER(), edPair.PublicSPKIDER()); err == nil || pair != nil {
		t.Fatal("NewKeyPair accepted mismatching public material")
	}
	if pair, err := NewKeyPair(AlgorithmEd25519SHA256, rsaPair.PrivatePKCS8DER(), rsaPair.PublicSPKIDER()); err == nil || pair != nil {
		t.Fatal("NewKeyPair accepted an algorithm mismatch")
	}
	noncanonical := append(rsaPair.PrivatePKCS8DER(), 0)
	if pair, err := NewKeyPair(AlgorithmRSASHA256, noncanonical, rsaPair.PublicSPKIDER()); err == nil || pair != nil {
		t.Fatal("NewKeyPair accepted noncanonical private DER")
	}
}

func TestNewKeyMaterialRejectsProfileUseUnsupportedByNativeSigningBridge(t *testing.T) {
	pair, err := GenerateEd25519KeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	material, err := NewKeyMaterial(
		1, "tenant", "example.test", ProfileUseNextDomainTransit, "handle", pair,
	)
	if err == nil || material != nil {
		t.Fatal("NewKeyMaterial accepted next-domain use unsupported by native key custody")
	}
}

func TestGenerationValidationAndDetachedBuilder(t *testing.T) {
	generation := testGeneration(t, 7, "one.example")
	defer func() { _ = generation.Close() }()
	if generation.Number() != 7 || generation.State() != DatasetStateCommitted {
		t.Fatalf("unexpected generation metadata")
	}
	clone, err := generation.Clone()
	if err != nil {
		t.Fatalf("Clone() error = %v", err)
	}
	defer func() { _ = clone.Close() }()
	if !generation.Equivalent(clone) {
		t.Fatal("generation clone differs")
	}

	builder, err := generation.NextBuilder(8, DatasetStateStaging)
	if err != nil {
		t.Fatalf("NextBuilder() error = %v", err)
	}
	defer func() { _ = builder.Close() }()
	second := testRecords(t, 8, "two.example", "two", AlgorithmEd25519SHA256)
	defer func() { _ = second.material.Close() }()
	if err := builder.AddProfileWithKeys(second.profile, []Credential{second.credential}, second.policy, []*KeyMaterial{second.material}); err != nil {
		t.Fatalf("AddProfileWithKeys() error = %v", err)
	}
	candidate, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	if candidate.Number() != 8 || len(candidate.Profiles()) != 2 {
		t.Fatalf("candidate did not preserve and add records")
	}
	if _, found := candidate.ProfileByDomain("one.example"); !found {
		t.Fatal("unrelated domain was not preserved")
	}
	if _, found := candidate.CredentialByDomainSelector("two.example", second.credential.Selector()); !found {
		t.Fatal("new exact selector lookup failed")
	}
}

func TestGenerationRejectsDuplicateAndIncompleteRelationships(t *testing.T) {
	records := testRecords(t, 11, "example.test", "one", AlgorithmRSASHA256)
	defer func() { _ = records.material.Close() }()
	if generation, err := NewGeneration(
		11,
		[]Handle{records.handle, records.handle},
		[]Profile{records.profile},
		[]Credential{records.credential},
		[]Policy{records.policy},
		[]*KeyMaterial{records.material},
	); err == nil || generation != nil {
		t.Fatal("NewGeneration accepted a duplicate handle")
	}
	if generation, err := NewGeneration(
		11,
		[]Handle{records.handle},
		[]Profile{records.profile},
		[]Credential{records.credential},
		[]Policy{records.policy},
		nil,
	); err == nil || generation != nil {
		t.Fatal("NewGeneration accepted missing key material")
	}
}

func TestGenerationRejectsCredentialWithOversizedCompositeOwner(t *testing.T) {
	domain := strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63)
	records := testRecords(t, 12, domain, "owner", AlgorithmEd25519SHA256)
	defer func() { _ = records.material.Close() }()
	credential, err := NewCredential(
		12, records.profile.ID(), strings.Repeat("s", 63), records.credential.Algorithm(),
		records.credential.PublicSPKIDER(), records.credential.HandleID(),
	)
	if err != nil {
		t.Fatalf("credential components should be independently valid: %v", err)
	}
	if generation, err := NewGeneration(
		12, []Handle{records.handle}, []Profile{records.profile}, []Credential{credential},
		[]Policy{records.policy}, []*KeyMaterial{records.material},
	); err == nil || generation != nil {
		t.Fatal("NewGeneration accepted an oversized composite DNS owner")
	}
}

type testRecordSet struct {
	handle     Handle
	profile    Profile
	credential Credential
	policy     Policy
	material   *KeyMaterial
}

func testGeneration(t *testing.T, generation uint64, domain string) *Generation {
	t.Helper()
	records := testRecords(t, generation, domain, "one", AlgorithmRSASHA256)
	defer func() { _ = records.material.Close() }()
	result, err := NewGeneration(
		generation,
		[]Handle{records.handle},
		[]Profile{records.profile},
		[]Credential{records.credential},
		[]Policy{records.policy},
		[]*KeyMaterial{records.material},
	)
	if err != nil {
		t.Fatalf("NewGeneration() error = %v", err)
	}
	return result
}

func testRecords(t *testing.T, generation uint64, domain, suffix string, algorithm Algorithm) testRecordSet {
	t.Helper()
	var pair *KeyPair
	var err error
	if algorithm == AlgorithmRSASHA256 {
		pair, err = GenerateRSAKeyPair(DefaultRSABits, nil)
	} else {
		pair, err = GenerateEd25519KeyPair(nil)
	}
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	defer func() { _ = pair.Close() }()
	handle, err := NewHandle(generation, "handle-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewProfile(generation, "profile-"+suffix, domain, RecordStatusDisabled, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredential(generation, profile.ID(), "selector-"+suffix, algorithm, pair.PublicSPKIDER(), handle.ID())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(
		generation, "tenant", domain, ProfileUseOriginator, profile.ID(),
		RecordStatusDisabled, RolloutOff, CompatibilityStrict, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewKeyMaterial(
		generation, "tenant", domain, ProfileUseOriginator, handle.ID(), pair,
	)
	if err != nil {
		t.Fatal(err)
	}
	return testRecordSet{handle: handle, profile: profile, credential: credential, policy: policy, material: material}
}
