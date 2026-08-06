package dkim2model

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// Handle declares one exact provider-neutral private-key handle.
type Handle struct {
	generation uint64
	id         string
}

// NewHandle validates one generation-specific handle declaration.
func NewHandle(generation uint64, id string) (Handle, error) {
	if generation == 0 || ValidateIdentifier(id) != nil {
		return Handle{}, ErrInvalid
	}
	return Handle{generation: generation, id: id}, nil
}

// Generation returns the immutable record generation.
func (h Handle) Generation() uint64 { return h.generation }

// ID returns the exact provider-neutral handle identifier.
func (h Handle) ID() string { return h.id }

// Profile contains one immutable DKIM2 signing-profile record.
type Profile struct {
	generation uint64
	id         string
	domain     string
	status     RecordStatus
	notBefore  time.Time
	notAfter   time.Time
}

// NewProfile validates one immutable signing-profile record.
func NewProfile(
	generation uint64,
	id string,
	domain string,
	status RecordStatus,
	notBefore time.Time,
	notAfter time.Time,
) (Profile, error) {
	if generation == 0 || ValidateIdentifier(id) != nil ||
		ValidateCanonicalDNSName(domain) != nil || !status.Known() {
		return Profile{}, ErrInvalid
	}
	windowPresent := !notBefore.IsZero() || !notAfter.IsZero()
	if windowPresent && (notBefore.IsZero() || notAfter.IsZero() ||
		!notBefore.Before(notAfter) || notBefore.Location() != time.UTC ||
		notAfter.Location() != time.UTC) {
		return Profile{}, ErrInvalid
	}
	return Profile{
		generation: generation, id: id, domain: domain, status: status,
		notBefore: notBefore, notAfter: notAfter,
	}, nil
}

// Generation returns the immutable record generation.
func (p Profile) Generation() uint64 { return p.generation }

// ID returns the exact profile identifier.
func (p Profile) ID() string { return p.id }

// SigningDomain returns the canonical lowercase signing domain.
func (p Profile) SigningDomain() string { return p.domain }

// Status returns the exact administrative profile status.
func (p Profile) Status() RecordStatus { return p.status }

// ValidityWindow returns the optional half-open UTC validity window.
func (p Profile) ValidityWindow() (time.Time, time.Time, bool) {
	if p.notBefore.IsZero() || p.notAfter.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return p.notBefore, p.notAfter, true
}

// WithStatus returns a detached profile record with a changed status.
func (p Profile) WithStatus(status RecordStatus) (Profile, error) {
	return NewProfile(p.generation, p.id, p.domain, status, p.notBefore, p.notAfter)
}

// Credential contains one immutable public credential and opaque handle binding.
type Credential struct {
	generation uint64
	profileID  string
	selector   string
	algorithm  Algorithm
	publicSPKI []byte
	handleID   string
}

// NewCredential validates one exact immutable public credential.
func NewCredential(
	generation uint64,
	profileID string,
	selector string,
	algorithm Algorithm,
	publicSPKI []byte,
	handleID string,
) (Credential, error) {
	if generation == 0 || ValidateIdentifier(profileID) != nil ||
		ValidateCanonicalDNSName(selector) != nil || !algorithm.Known() ||
		ValidateIdentifier(handleID) != nil || len(publicSPKI) == 0 ||
		len(publicSPKI) > 2<<10 {
		return Credential{}, ErrInvalid
	}
	if _, err := canonicalDNSPublicBytes(algorithm, publicSPKI); err != nil {
		return Credential{}, err
	}
	return Credential{
		generation: generation, profileID: profileID, selector: selector,
		algorithm: algorithm, publicSPKI: bytes.Clone(publicSPKI), handleID: handleID,
	}, nil
}

// Generation returns the immutable record generation.
func (c Credential) Generation() uint64 { return c.generation }

// ProfileID returns the exact owning profile identifier.
func (c Credential) ProfileID() string { return c.profileID }

// Selector returns the canonical lowercase selector.
func (c Credential) Selector() string { return c.selector }

// Algorithm returns the exact signing algorithm.
func (c Credential) Algorithm() Algorithm { return c.algorithm }

// PublicSPKIDER returns detached canonical public SubjectPublicKeyInfo DER.
func (c Credential) PublicSPKIDER() []byte { return bytes.Clone(c.publicSPKI) }

// DNSPublicKeyBytes returns detached algorithm-specific DNS p= bytes.
func (c Credential) DNSPublicKeyBytes() []byte {
	result, _ := canonicalDNSPublicBytes(c.algorithm, c.publicSPKI)
	return result
}

// MatchesDNSPublicKeyBytes accepts every canonical DNS encoding of this exact public key.
func (c Credential) MatchesDNSPublicKeyBytes(candidate []byte) bool {
	return DNSPublicKeyMatchesSPKI(c.algorithm, c.publicSPKI, candidate)
}

// HandleID returns the exact provider-neutral handle identifier.
func (c Credential) HandleID() string { return c.handleID }

// Policy contains one immutable exact tenant/domain/profile-use binding.
type Policy struct {
	generation      uint64
	tenantID        string
	domain          string
	use             ProfileUse
	profileID       string
	status          RecordStatus
	rollout         Rollout
	compatibility   Compatibility
	feedbackRouteID string
}

// NewPolicy validates one exact immutable administrative policy.
func NewPolicy(
	generation uint64,
	tenantID string,
	domain string,
	use ProfileUse,
	profileID string,
	status RecordStatus,
	rollout Rollout,
	compatibility Compatibility,
	feedbackRouteID string,
) (Policy, error) {
	if generation == 0 || ValidateIdentifier(tenantID) != nil ||
		ValidateCanonicalDNSName(domain) != nil || !use.Known() ||
		ValidateIdentifier(profileID) != nil || !status.Known() ||
		!rollout.Known() || compatibility != CompatibilityStrict ||
		(feedbackRouteID != "" && ValidateIdentifier(feedbackRouteID) != nil) {
		return Policy{}, ErrInvalid
	}
	return Policy{
		generation: generation, tenantID: tenantID, domain: domain, use: use,
		profileID: profileID, status: status, rollout: rollout,
		compatibility: compatibility, feedbackRouteID: feedbackRouteID,
	}, nil
}

// Generation returns the immutable record generation.
func (p Policy) Generation() uint64 { return p.generation }

// TenantID returns the exact administrative tenant identifier.
func (p Policy) TenantID() string { return p.tenantID }

// SigningDomain returns the canonical lowercase signing domain.
func (p Policy) SigningDomain() string { return p.domain }

// Use returns the exact administrative profile use.
func (p Policy) Use() ProfileUse { return p.use }

// ProfileID returns the exact referenced profile identifier.
func (p Policy) ProfileID() string { return p.profileID }

// Status returns the exact administrative policy status.
func (p Policy) Status() RecordStatus { return p.status }

// Rollout returns the exact administrative rollout state.
func (p Policy) Rollout() Rollout { return p.rollout }

// Compatibility returns the exact strict compatibility contract.
func (p Policy) Compatibility() Compatibility { return p.compatibility }

// FeedbackRouteID returns the optional exact feedback-route identifier.
func (p Policy) FeedbackRouteID() string { return p.feedbackRouteID }

// WithActivation returns a policy record with changed status and rollout.
func (p Policy) WithActivation(status RecordStatus, rollout Rollout) (Policy, error) {
	return NewPolicy(
		p.generation, p.tenantID, p.domain, p.use, p.profileID, status, rollout,
		p.compatibility, p.feedbackRouteID,
	)
}

// canonicalDNSPublicBytes validates canonical SPKI and returns DNS p= bytes.
func canonicalDNSPublicBytes(algorithm Algorithm, publicSPKI []byte) ([]byte, error) {
	parsed, err := x509.ParsePKIXPublicKey(publicSPKI)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil || !bytes.Equal(canonical, publicSPKI) {
		clear(canonical)
		return nil, ErrInvalid
	}
	clear(canonical)
	switch public := parsed.(type) {
	case *rsa.PublicKey:
		if algorithm != AlgorithmRSASHA256 || public == nil || public.N == nil ||
			public.N.Sign() <= 0 || public.N.Bit(0) != 1 ||
			public.N.BitLen() < MinRSABits || public.N.BitLen() > MaxRSABits ||
			public.E != requiredRSAExponent {
			return nil, ErrInvalid
		}
		return bytes.Clone(publicSPKI), nil
	case ed25519.PublicKey:
		if algorithm != AlgorithmEd25519SHA256 || len(public) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		return bytes.Clone(public), nil
	default:
		return nil, ErrInvalid
	}
}

// DNSPublicKeyMatchesSPKI compares a DNS payload with canonical LDAP SPKI.
func DNSPublicKeyMatchesSPKI(algorithm Algorithm, publicSPKI, candidate []byte) bool {
	primary, err := canonicalDNSPublicBytes(algorithm, publicSPKI)
	if err != nil {
		return false
	}
	defer clear(primary)
	if bytes.Equal(primary, candidate) {
		return true
	}
	if algorithm != AlgorithmRSASHA256 {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(publicSPKI)
	if err != nil {
		return false
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return false
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(public)
	defer clear(pkcs1)
	return bytes.Equal(pkcs1, candidate)
}

// cloneCredential returns one detached immutable credential.
func cloneCredential(input Credential) Credential {
	input.publicSPKI = bytes.Clone(input.publicSPKI)
	return input
}

// rebaseRecordGeneration returns one handle in a successor generation.
func rebaseHandle(input Handle, generation uint64) Handle {
	input.generation = generation
	return input
}

// rebaseProfile returns one profile in a successor generation.
func rebaseProfile(input Profile, generation uint64) Profile {
	input.generation = generation
	return input
}

// rebaseCredential returns one detached credential in a successor generation.
func rebaseCredential(input Credential, generation uint64) Credential {
	input = cloneCredential(input)
	input.generation = generation
	return input
}

// rebasePolicy returns one policy in a successor generation.
func rebasePolicy(input Policy, generation uint64) Policy {
	input.generation = generation
	return input
}
