package dkim2model

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"io"
)

const (
	// compositeSeedBytes is the size of each component seed: the FIPS 204
	// ML-DSA-44 seed and the RFC 8032 Ed25519 seed.
	compositeSeedBytes = 32
	// compositePrivateKeyBytes is the raw composite private key: the ML-DSA-44
	// seed followed by the Ed25519 seed.
	compositePrivateKeyBytes = 2 * compositeSeedBytes
	// mldsa44PublicKeyBytes is the FIPS 204 ML-DSA-44 public key size.
	mldsa44PublicKeyBytes = 1312
	// CompositePublicKeyBytes is the raw DNS p= size of an
	// mldsa44-ed25519-sha512 key: the ML-DSA-44 public key followed by the
	// Ed25519 public key.
	CompositePublicKeyBytes = mldsa44PublicKeyBytes + ed25519.PublicKeySize
)

// compositePKCS8Prefix is the fixed DER prefix of an id-MLDSA44-Ed25519-SHA512
// (OID 1.3.6.1.5.5.7.6.39) PKCS#8 OneAsymmetricKey whose privateKey OCTET
// STRING holds the 64-byte seed concatenation. It matches the DKIM2 reference
// implementation byte for byte.
var compositePKCS8Prefix = []byte{
	0x30, 0x51, 0x02, 0x01, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06,
	0x27, 0x04, 0x40,
}

// compositeSPKIPrefix is the fixed DER prefix of an id-MLDSA44-Ed25519-SHA512
// SubjectPublicKeyInfo whose BIT STRING holds the raw 1344-byte public key.
var compositeSPKIPrefix = []byte{
	0x30, 0x82, 0x05, 0x51, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x27,
	0x03, 0x82, 0x05, 0x41, 0x00,
}

// GenerateCompositeKeyPair creates one mldsa44-ed25519-sha512 key from 64
// bytes of random with its exact PKCS#8, SPKI, and raw DNS encodings.
func GenerateCompositeKeyPair(random io.Reader) (*KeyPair, error) {
	if random == nil {
		random = rand.Reader
	}
	seeds := make([]byte, compositePrivateKeyBytes)
	defer clear(seeds)
	if _, err := io.ReadFull(random, seeds); err != nil {
		return nil, ErrInvalid
	}
	raw, err := compositePublicFromSeeds(seeds)
	if err != nil {
		return nil, err
	}
	privateDER := append(bytes.Clone(compositePKCS8Prefix), seeds...)
	defer clear(privateDER)
	publicDER := append(bytes.Clone(compositeSPKIPrefix), raw...)
	return NewKeyPair(AlgorithmMLDSA44Ed25519SHA512, privateDER, publicDER)
}

// compositePublicFromSeeds derives the raw 1344-byte composite public key
// from the 64-byte seed concatenation. An all-zero component seed is rejected.
// The expanded ML-DSA-44 private key is owned by crypto/mldsa and cannot be
// zeroed; it is released with this call, so clearing covers only the seeds
// and the Ed25519 key.
func compositePublicFromSeeds(seeds []byte) ([]byte, error) {
	if len(seeds) != compositePrivateKeyBytes || allZero(seeds[:compositeSeedBytes]) ||
		allZero(seeds[compositeSeedBytes:]) {
		return nil, ErrInvalid
	}
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seeds[:compositeSeedBytes])
	if err != nil {
		return nil, ErrInvalid
	}
	edPrivate := ed25519.NewKeyFromSeed(seeds[compositeSeedBytes:])
	defer clear(edPrivate)
	mlPublic := mlKey.PublicKey().Bytes()
	if len(mlPublic) != mldsa44PublicKeyBytes {
		return nil, ErrInvalid
	}
	return append(mlPublic, edPrivate.Public().(ed25519.PublicKey)...), nil
}

// validateCompositeKey proves the exact composite PKCS#8 and SPKI encodings
// and that the private seeds derive the public key; it returns the raw DNS
// p= bytes.
func validateCompositeKey(privatePKCS8, publicSPKI []byte) ([]byte, error) {
	if len(privatePKCS8) != len(compositePKCS8Prefix)+compositePrivateKeyBytes ||
		!bytes.HasPrefix(privatePKCS8, compositePKCS8Prefix) {
		return nil, ErrInvalid
	}
	raw, err := compositeDNSPublicBytes(publicSPKI)
	if err != nil {
		return nil, err
	}
	derived, err := compositePublicFromSeeds(privatePKCS8[len(compositePKCS8Prefix):])
	if err != nil || !bytes.Equal(derived, raw) {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

// compositeDNSPublicBytes validates the exact composite SPKI and returns the
// raw 1344-byte DNS p= key after checking that the ML-DSA-44 half decodes.
func compositeDNSPublicBytes(publicSPKI []byte) ([]byte, error) {
	if len(publicSPKI) != len(compositeSPKIPrefix)+CompositePublicKeyBytes ||
		!bytes.HasPrefix(publicSPKI, compositeSPKIPrefix) {
		return nil, ErrInvalid
	}
	raw := bytes.Clone(publicSPKI[len(compositeSPKIPrefix):])
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA44(), raw[:mldsa44PublicKeyBytes]); err != nil {
		return nil, ErrInvalid
	}
	return raw, nil
}
