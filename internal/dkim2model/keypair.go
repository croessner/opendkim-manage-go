package dkim2model

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sync"
)

const (
	// DefaultRSABits is the restrictive default for newly generated RSA keys.
	DefaultRSABits = 2048
	// MinRSABits is the minimum accepted native RSA modulus size.
	MinRSABits = 2048
	// MaxRSABits is the maximum accepted native RSA modulus size.
	MaxRSABits          = 8192
	requiredRSAExponent = 65537
	keyPairRedacted     = "dkim2model.KeyPair{redacted}"
)

// KeyPair owns one validated native key in all required storage and DNS forms.
type KeyPair struct {
	mu           sync.RWMutex
	algorithm    Algorithm
	privatePKCS8 []byte
	publicSPKI   []byte
	dnsPublic    []byte
	closed       bool
}

// GenerateKeyPair creates one native key using the algorithm-specific contract.
func GenerateKeyPair(algorithm Algorithm, rsaBits int, random io.Reader) (*KeyPair, error) {
	switch algorithm {
	case AlgorithmRSASHA256:
		return GenerateRSAKeyPair(rsaBits, random)
	case AlgorithmEd25519SHA256:
		return GenerateEd25519KeyPair(random)
	default:
		return nil, ErrInvalid
	}
}

// GenerateRSAKeyPair creates one RSA key with canonical PKCS#8 and SPKI encodings.
func GenerateRSAKeyPair(bits int, random io.Reader) (*KeyPair, error) {
	if bits < MinRSABits || bits > MaxRSABits || bits%8 != 0 {
		return nil, ErrInvalid
	}
	if random == nil {
		random = rand.Reader
	}
	private, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	defer clearPrivateKey(private)
	if private.E != requiredRSAExponent || private.Validate() != nil {
		return nil, ErrInvalid
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("marshal RSA private key: %w", err)
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal RSA public key: %w", err)
	}
	defer clear(publicDER)
	return NewKeyPair(AlgorithmRSASHA256, privateDER, publicDER)
}

// GenerateEd25519KeyPair creates one Ed25519 key with canonical PKCS#8 and SPKI encodings.
func GenerateEd25519KeyPair(random io.Reader) (*KeyPair, error) {
	if random == nil {
		random = rand.Reader
	}
	public, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	defer clear(private)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 private key: %w", err)
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 public key: %w", err)
	}
	defer clear(publicDER)
	return NewKeyPair(AlgorithmEd25519SHA256, privateDER, publicDER)
}

// NewKeyPair validates canonical private/public agreement and detaches all bytes.
func NewKeyPair(algorithm Algorithm, privatePKCS8, publicSPKI []byte) (*KeyPair, error) {
	if !algorithm.Known() || len(privatePKCS8) == 0 || len(publicSPKI) == 0 ||
		len(privatePKCS8) > 16<<10 || len(publicSPKI) > 2<<10 {
		return nil, ErrInvalid
	}
	private, err := x509.ParsePKCS8PrivateKey(privatePKCS8)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clearPrivateKey(private)
	canonicalPrivate, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil || !bytes.Equal(canonicalPrivate, privatePKCS8) {
		clear(canonicalPrivate)
		return nil, ErrInvalid
	}
	clear(canonicalPrivate)

	public, err := x509.ParsePKIXPublicKey(publicSPKI)
	if err != nil {
		return nil, ErrInvalid
	}
	canonicalPublic, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(canonicalPublic, publicSPKI) {
		clear(canonicalPublic)
		return nil, ErrInvalid
	}
	defer clear(canonicalPublic)

	dnsPublic, err := validateKeyRelationship(algorithm, private, public)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		algorithm: algorithm, privatePKCS8: bytes.Clone(privatePKCS8),
		publicSPKI: bytes.Clone(publicSPKI), dnsPublic: dnsPublic,
	}, nil
}

// validateKeyRelationship proves exact algorithm, policy, and public-key agreement.
func validateKeyRelationship(algorithm Algorithm, private, public any) ([]byte, error) {
	switch typedPrivate := private.(type) {
	case *rsa.PrivateKey:
		typedPublic, ok := public.(*rsa.PublicKey)
		if algorithm != AlgorithmRSASHA256 || !ok || typedPrivate == nil ||
			typedPrivate.Validate() != nil || len(typedPrivate.Primes) != 2 ||
			typedPrivate.N == nil || typedPrivate.N.BitLen() < MinRSABits ||
			typedPrivate.N.BitLen() > MaxRSABits || typedPrivate.E != requiredRSAExponent ||
			typedPublic.N == nil || typedPrivate.N.Cmp(typedPublic.N) != 0 ||
			typedPrivate.E != typedPublic.E {
			return nil, ErrInvalid
		}
		return x509.MarshalPKIXPublicKey(typedPublic)
	case ed25519.PrivateKey:
		typedPublic, ok := public.(ed25519.PublicKey)
		if algorithm != AlgorithmEd25519SHA256 || !ok ||
			len(typedPrivate) != ed25519.PrivateKeySize ||
			len(typedPublic) != ed25519.PublicKeySize ||
			!bytes.Equal(typedPrivate.Public().(ed25519.PublicKey), typedPublic) {
			return nil, ErrInvalid
		}
		return bytes.Clone(typedPublic), nil
	default:
		return nil, ErrInvalid
	}
}

// Algorithm returns the exact signing algorithm or its zero value after Close.
func (k *KeyPair) Algorithm() Algorithm {
	if k == nil {
		return ""
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return ""
	}
	return k.algorithm
}

// PrivatePKCS8DER returns detached canonical unencrypted private PKCS#8 DER.
func (k *KeyPair) PrivatePKCS8DER() []byte {
	return k.cloneBytes(func() []byte { return k.privatePKCS8 })
}

// PublicSPKIDER returns detached canonical public SubjectPublicKeyInfo DER.
func (k *KeyPair) PublicSPKIDER() []byte { return k.cloneBytes(func() []byte { return k.publicSPKI }) }

// DNSPublicKeyBytes returns detached algorithm-specific DNS p= bytes.
func (k *KeyPair) DNSPublicKeyBytes() []byte {
	return k.cloneBytes(func() []byte { return k.dnsPublic })
}

// cloneBytes returns a detached protected buffer while holding the owner lock.
func (k *KeyPair) cloneBytes(selectBytes func() []byte) []byte {
	if k == nil {
		return nil
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil
	}
	return bytes.Clone(selectBytes())
}

// Clone returns one independently owned copy of the validated key pair.
func (k *KeyPair) Clone() (*KeyPair, error) {
	if k == nil {
		return nil, ErrInvalid
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosed
	}
	return &KeyPair{
		algorithm: k.algorithm, privatePKCS8: bytes.Clone(k.privatePKCS8),
		publicSPKI: bytes.Clone(k.publicSPKI), dnsPublic: bytes.Clone(k.dnsPublic),
	}, nil
}

// Equivalent compares the exact validated encoded key facts without exposing them.
func (k *KeyPair) Equivalent(other *KeyPair) bool {
	if k == nil || other == nil {
		return false
	}
	leftPrivate := k.PrivatePKCS8DER()
	defer clear(leftPrivate)
	rightPrivate := other.PrivatePKCS8DER()
	defer clear(rightPrivate)
	leftPublic := k.PublicSPKIDER()
	rightPublic := other.PublicSPKIDER()
	leftDNS := k.DNSPublicKeyBytes()
	rightDNS := other.DNSPublicKeyBytes()
	return k.Algorithm().Known() && k.Algorithm() == other.Algorithm() &&
		bytes.Equal(leftPrivate, rightPrivate) && bytes.Equal(leftPublic, rightPublic) &&
		bytes.Equal(leftDNS, rightDNS)
}

// Close clears all retained encoded key material and invalidates this owner.
func (k *KeyPair) Close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	clear(k.privatePKCS8)
	clear(k.publicSPKI)
	clear(k.dnsPublic)
	k.privatePKCS8 = nil
	k.publicSPKI = nil
	k.dnsPublic = nil
	k.algorithm = ""
	k.closed = true
	return nil
}

// String returns a constant protected summary.
func (*KeyPair) String() string { return keyPairRedacted }

// GoString returns a constant protected representation.
func (*KeyPair) GoString() string { return keyPairRedacted }

// Format prevents formatting verbs from traversing protected key state.
func (*KeyPair) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, keyPairRedacted) }

// MarshalJSON emits an empty object without key material.
func (*KeyPair) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// clearPrivateKey best-effort clears mutable private-key storage.
func clearPrivateKey(key crypto.PrivateKey) {
	switch typed := key.(type) {
	case ed25519.PrivateKey:
		clear(typed)
	case *rsa.PrivateKey:
		if typed == nil {
			return
		}
		clearBigInt(typed.D)
		for _, prime := range typed.Primes {
			clearBigInt(prime)
		}
		clearBigInt(typed.Precomputed.Dp)
		clearBigInt(typed.Precomputed.Dq)
		clearBigInt(typed.Precomputed.Qinv)
	}
}

// clearBigInt best-effort overwrites one mutable big integer.
func clearBigInt(value *big.Int) {
	if value != nil {
		value.SetInt64(0)
	}
}
