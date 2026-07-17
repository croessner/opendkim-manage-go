package dkim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type Keys struct {
	rsaBits         int
	rsaPrivatePEM   string
	rsaPublicBase64 string
	edPrivatePEM    string
	edPublicBase64  string
}

func NewKeys() *Keys {
	return &Keys{rsaBits: 2048}
}

func (k *Keys) SetRSABits(bits int) error {
	if bits <= 1024 {
		return fmt.Errorf("RSA bits must be greater than 1024")
	}
	k.rsaBits = bits
	return nil
}

func (k *Keys) GenerateRSA() error {
	priv, err := rsa.GenerateKey(rand.Reader, k.rsaBits)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	k.rsaPrivatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal rsa public key: %w", err)
	}
	k.rsaPublicBase64 = base64.StdEncoding.EncodeToString(pubDER)
	return nil
}

func (k *Keys) GeneratePublicRSA(privatePEM string) error {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return fmt.Errorf("invalid rsa private key pem")
	}
	var priv any
	var err error
	if block.Type == "RSA PRIVATE KEY" {
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return fmt.Errorf("parse rsa private key: %w", err)
	}

	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal rsa public key: %w", err)
	}
	k.rsaPublicBase64 = base64.StdEncoding.EncodeToString(pubDER)
	return nil
}

func (k *Keys) GenerateED25519() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal ed25519 private key: %w", err)
	}
	k.edPrivatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	k.edPublicBase64 = base64.StdEncoding.EncodeToString(pub)
	return nil
}

func (k *Keys) GeneratePublicED25519(privatePEM string) error {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return fmt.Errorf("invalid ed25519 private key pem")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse ed25519 private key: %w", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not ed25519")
	}
	pub := priv.Public().(ed25519.PublicKey)
	k.edPublicBase64 = base64.StdEncoding.EncodeToString(pub)
	return nil
}

func (k *Keys) RSAPrivateKey() string {
	return k.rsaPrivatePEM
}

func (k *Keys) RSAPublicKey() string {
	return k.rsaPublicBase64
}

func (k *Keys) ED25519PrivateKey() string {
	return k.edPrivatePEM
}

func (k *Keys) ED25519PublicKey() string {
	return k.edPublicBase64
}
