package dkim2model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const keyMaterialRedacted = "dkim2model.KeyMaterial{redacted}"

// KeyMaterial owns one native immutable private key and its exact policy binding.
type KeyMaterial struct {
	mu         sync.RWMutex
	generation uint64
	tenantID   string
	domain     string
	use        ProfileUse
	handleID   string
	pair       *KeyPair
	closed     bool
}

// NewKeyMaterial validates and detaches one native key-material record.
func NewKeyMaterial(
	generation uint64,
	tenantID string,
	domain string,
	use ProfileUse,
	handleID string,
	pair *KeyPair,
) (*KeyMaterial, error) {
	if generation == 0 || ValidateIdentifier(tenantID) != nil ||
		ValidateCanonicalDNSName(domain) != nil || !use.SupportsNativeKeyCustody() ||
		ValidateIdentifier(handleID) != nil || pair == nil || !pair.Algorithm().Known() {
		return nil, ErrInvalid
	}
	owned, err := pair.Clone()
	if err != nil {
		return nil, err
	}
	return &KeyMaterial{
		generation: generation, tenantID: tenantID, domain: domain, use: use,
		handleID: handleID, pair: owned,
	}, nil
}

// NewKeyMaterialDER validates canonical encoded material and detaches every buffer.
func NewKeyMaterialDER(
	generation uint64,
	tenantID string,
	domain string,
	use ProfileUse,
	handleID string,
	algorithm Algorithm,
	publicSPKI []byte,
	privatePKCS8 []byte,
) (*KeyMaterial, error) {
	pair, err := NewKeyPair(algorithm, privatePKCS8, publicSPKI)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pair.Close() }()
	return NewKeyMaterial(generation, tenantID, domain, use, handleID, pair)
}

// Generation returns the immutable record generation.
func (m *KeyMaterial) Generation() uint64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0
	}
	return m.generation
}

// TenantID returns the exact administrative tenant identifier.
func (m *KeyMaterial) TenantID() string { return m.readString(func() string { return m.tenantID }) }

// SigningDomain returns the canonical lowercase signing domain.
func (m *KeyMaterial) SigningDomain() string { return m.readString(func() string { return m.domain }) }

// Use returns the exact administrative profile use.
func (m *KeyMaterial) Use() ProfileUse {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ""
	}
	return m.use
}

// HandleID returns the exact provider-neutral handle identifier.
func (m *KeyMaterial) HandleID() string { return m.readString(func() string { return m.handleID }) }

// Algorithm returns the exact native key algorithm.
func (m *KeyMaterial) Algorithm() Algorithm {
	pair := m.pairSnapshot()
	if pair == nil {
		return ""
	}
	return pair.Algorithm()
}

// PrivatePKCS8DER returns detached canonical unencrypted private PKCS#8 DER.
func (m *KeyMaterial) PrivatePKCS8DER() []byte {
	pair := m.pairSnapshot()
	if pair == nil {
		return nil
	}
	return pair.PrivatePKCS8DER()
}

// PublicSPKIDER returns detached canonical public SubjectPublicKeyInfo DER.
func (m *KeyMaterial) PublicSPKIDER() []byte {
	pair := m.pairSnapshot()
	if pair == nil {
		return nil
	}
	return pair.PublicSPKIDER()
}

// DNSPublicKeyBytes returns detached algorithm-specific DNS p= bytes.
func (m *KeyMaterial) DNSPublicKeyBytes() []byte {
	pair := m.pairSnapshot()
	if pair == nil {
		return nil
	}
	return pair.DNSPublicKeyBytes()
}

// readString returns one non-secret record value under the owner lock.
func (m *KeyMaterial) readString(selectValue func() string) string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ""
	}
	return selectValue()
}

// pairSnapshot returns the retained immutable key-pair pointer under the owner lock.
func (m *KeyMaterial) pairSnapshot() *KeyPair {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil
	}
	return m.pair
}

// Clone returns one independently owned copy of the complete key-material record.
func (m *KeyMaterial) Clone() (*KeyMaterial, error) {
	if m == nil {
		return nil, ErrInvalid
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed || m.pair == nil {
		return nil, ErrClosed
	}
	pair, err := m.pair.Clone()
	if err != nil {
		return nil, err
	}
	return &KeyMaterial{
		generation: m.generation, tenantID: m.tenantID, domain: m.domain,
		use: m.use, handleID: m.handleID, pair: pair,
	}, nil
}

// Equivalent compares exact binding and encoded key facts without exposing them.
func (m *KeyMaterial) Equivalent(other *KeyMaterial) bool {
	if m == nil || other == nil {
		return false
	}
	leftPrivate := m.PrivatePKCS8DER()
	defer clear(leftPrivate)
	rightPrivate := other.PrivatePKCS8DER()
	defer clear(rightPrivate)
	return m.Generation() != 0 && m.Generation() == other.Generation() &&
		m.TenantID() == other.TenantID() &&
		m.SigningDomain() == other.SigningDomain() && m.Use() == other.Use() &&
		m.HandleID() == other.HandleID() && m.Algorithm() == other.Algorithm() &&
		bytes.Equal(leftPrivate, rightPrivate) &&
		bytes.Equal(m.PublicSPKIDER(), other.PublicSPKIDER())
}

// rebaseKeyMaterial clones one key-material record into a successor generation.
func rebaseKeyMaterial(input *KeyMaterial, generation uint64) (*KeyMaterial, error) {
	clone, err := input.Clone()
	if err != nil {
		return nil, err
	}
	clone.generation = generation
	return clone, nil
}

// Close clears the retained key pair and invalidates this record owner.
func (m *KeyMaterial) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	var err error
	if m.pair != nil {
		err = m.pair.Close()
	}
	m.pair = nil
	m.generation = 0
	m.tenantID = ""
	m.domain = ""
	m.use = ""
	m.handleID = ""
	m.closed = true
	return err
}

// String returns a constant protected summary.
func (*KeyMaterial) String() string { return keyMaterialRedacted }

// GoString returns a constant protected representation.
func (*KeyMaterial) GoString() string { return keyMaterialRedacted }

// Format prevents formatting verbs from traversing protected key state.
func (*KeyMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, keyMaterialRedacted)
}

// MarshalJSON emits an empty object without binding or key material.
func (*KeyMaterial) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }
