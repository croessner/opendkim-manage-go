package dkim

import "testing"

func TestGenerateRSAAndPublic(t *testing.T) {
	k := NewKeys()
	if err := k.SetRSABits(2048); err != nil {
		t.Fatalf("set bits: %v", err)
	}
	if err := k.GenerateRSA(); err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	if k.RSAPrivateKey() == "" || k.RSAPublicKey() == "" {
		t.Fatal("expected RSA key material")
	}
	clone := NewKeys()
	if err := clone.GeneratePublicRSA(k.RSAPrivateKey()); err != nil {
		t.Fatalf("derive public rsa: %v", err)
	}
	if clone.RSAPublicKey() != k.RSAPublicKey() {
		t.Fatal("derived RSA public key mismatch")
	}
}

func TestGenerateED25519AndPublic(t *testing.T) {
	k := NewKeys()
	if err := k.GenerateED25519(); err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	if k.ED25519PrivateKey() == "" || k.ED25519PublicKey() == "" {
		t.Fatal("expected ED25519 key material")
	}
	clone := NewKeys()
	if err := clone.GeneratePublicED25519(k.ED25519PrivateKey()); err != nil {
		t.Fatalf("derive public ed25519: %v", err)
	}
	if clone.ED25519PublicKey() != k.ED25519PublicKey() {
		t.Fatal("derived ED25519 public key mismatch")
	}
}
