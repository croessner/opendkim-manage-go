// Package dkim2model owns complete immutable DKIM2 datasource generations.
package dkim2model

import (
	"errors"
	"strings"
)

const (
	// SchemaVersion is the exact native DKIM2 datasource schema contract.
	SchemaVersion = "dkim2-datasource-v2"
	// MaxIdentifierBytes bounds every opaque administrative identifier.
	MaxIdentifierBytes = 128
)

var (
	// ErrInvalid identifies malformed or incomplete DKIM2 model input.
	ErrInvalid = errors.New("invalid DKIM2 model")
	// ErrClosed identifies access to cleared protected material.
	ErrClosed = errors.New("DKIM2 protected material is closed")
)

// Algorithm identifies one exact native signing algorithm.
type Algorithm string

const (
	// AlgorithmRSASHA256 identifies RSA with SHA-256.
	AlgorithmRSASHA256 Algorithm = "rsa-sha256"
	// AlgorithmEd25519SHA256 identifies Ed25519 with SHA-256.
	AlgorithmEd25519SHA256 Algorithm = "ed25519-sha256"
)

// ParseAlgorithm parses one exact closed algorithm value.
func ParseAlgorithm(value string) (Algorithm, error) {
	algorithm := Algorithm(value)
	if !algorithm.Known() {
		return "", ErrInvalid
	}
	return algorithm, nil
}

// Known reports whether the algorithm belongs to the closed vocabulary.
func (a Algorithm) Known() bool {
	return a == AlgorithmRSASHA256 || a == AlgorithmEd25519SHA256
}

// ProfileUse identifies one exact administrative signing purpose.
type ProfileUse string

const (
	// ProfileUseOriginator selects originator signing.
	ProfileUseOriginator ProfileUse = "originator"
	// ProfileUseOrdinaryTransit selects ordinary-transit signing.
	ProfileUseOrdinaryTransit ProfileUse = "ordinary_transit"
	// ProfileUseNextDomainTransit selects next-domain-transit signing.
	ProfileUseNextDomainTransit ProfileUse = "next_domain_transit"
	// ProfileUseDeliveryStatus selects delivery-status signing.
	ProfileUseDeliveryStatus ProfileUse = "delivery_status"
)

// ParseProfileUse parses one exact closed profile-use value.
func ParseProfileUse(value string) (ProfileUse, error) {
	use := ProfileUse(value)
	if !use.Known() {
		return "", ErrInvalid
	}
	return use, nil
}

// Known reports whether the profile use belongs to the closed vocabulary.
func (u ProfileUse) Known() bool {
	return u == ProfileUseOriginator || u == ProfileUseOrdinaryTransit ||
		u == ProfileUseNextDomainTransit || u == ProfileUseDeliveryStatus
}

// SupportsNativeKeyCustody reports whether the bound DKIM2 signing bridge can
// project private-key material for this administrative profile use.
func (u ProfileUse) SupportsNativeKeyCustody() bool {
	return u == ProfileUseOriginator || u == ProfileUseOrdinaryTransit ||
		u == ProfileUseDeliveryStatus
}

// RecordStatus identifies one exact administrative record state.
type RecordStatus string

const (
	// RecordStatusActive permits an otherwise eligible record.
	RecordStatusActive RecordStatus = "active"
	// RecordStatusDisabled closes an administrative record.
	RecordStatusDisabled RecordStatus = "disabled"
)

// ParseRecordStatus parses one exact closed record status.
func ParseRecordStatus(value string) (RecordStatus, error) {
	status := RecordStatus(value)
	if !status.Known() {
		return "", ErrInvalid
	}
	return status, nil
}

// Known reports whether the status belongs to the closed vocabulary.
func (s RecordStatus) Known() bool {
	return s == RecordStatusActive || s == RecordStatusDisabled
}

// Rollout identifies one exact administrative rollout state.
type Rollout string

const (
	// RolloutEnforce permits signing after all other checks.
	RolloutEnforce Rollout = "enforce"
	// RolloutObserve resolves records without permitting signing.
	RolloutObserve Rollout = "observe"
	// RolloutOff disables the administrative binding.
	RolloutOff Rollout = "off"
)

// ParseRollout parses one exact closed rollout value.
func ParseRollout(value string) (Rollout, error) {
	rollout := Rollout(value)
	if !rollout.Known() {
		return "", ErrInvalid
	}
	return rollout, nil
}

// Known reports whether the rollout belongs to the closed vocabulary.
func (r Rollout) Known() bool {
	return r == RolloutEnforce || r == RolloutObserve || r == RolloutOff
}

// Compatibility identifies one exact compatibility contract.
type Compatibility string

const (
	// CompatibilityStrict preserves every restrictive DKIM2 rule.
	CompatibilityStrict Compatibility = "strict"
)

// ParseCompatibility parses the one supported compatibility value.
func ParseCompatibility(value string) (Compatibility, error) {
	compatibility := Compatibility(value)
	if !compatibility.Known() {
		return "", ErrInvalid
	}
	return compatibility, nil
}

// Known reports whether the compatibility policy is supported.
func (c Compatibility) Known() bool { return c == CompatibilityStrict }

// DatasetState identifies one exact immutable publication state.
type DatasetState string

const (
	// DatasetStateStaging identifies a complete unpublished candidate.
	DatasetStateStaging DatasetState = "staging"
	// DatasetStateCommitted identifies a published immutable generation.
	DatasetStateCommitted DatasetState = "committed"
)

// ParseDatasetState parses one exact closed dataset state.
func ParseDatasetState(value string) (DatasetState, error) {
	state := DatasetState(value)
	if !state.Known() {
		return "", ErrInvalid
	}
	return state, nil
}

// Known reports whether the dataset state belongs to the closed vocabulary.
func (s DatasetState) Known() bool {
	return s == DatasetStateStaging || s == DatasetStateCommitted
}

// ValidateIdentifier enforces the canonical administrative identifier grammar.
func ValidateIdentifier(value string) error {
	if len(value) == 0 || len(value) > MaxIdentifierBytes || !identifierEdge(value[0]) {
		return ErrInvalid
	}
	for index := 1; index < len(value); index++ {
		candidate := value[index]
		if !identifierEdge(candidate) && candidate != '.' &&
			candidate != '_' && candidate != '-' {
			return ErrInvalid
		}
	}
	return nil
}

// CanonicalDomain validates an ASCII LDH domain and returns lowercase form.
func CanonicalDomain(value string) (string, error) { return canonicalDNSName(value) }

// CanonicalSelector validates an ASCII LDH selector and returns lowercase form.
func CanonicalSelector(value string) (string, error) { return canonicalDNSName(value) }

// ValidateCanonicalDNSName requires an already-canonical lowercase ASCII LDH name.
func ValidateCanonicalDNSName(value string) error {
	canonical, err := canonicalDNSName(value)
	if err != nil || canonical != value {
		return ErrInvalid
	}
	return nil
}

// ValidateDomainSelector enforces the complete canonical DNS owner contract.
func ValidateDomainSelector(domain, selector string) error {
	if ValidateCanonicalDNSName(domain) != nil || ValidateCanonicalDNSName(selector) != nil {
		return ErrInvalid
	}
	presentation := selector + "._domainkey." + domain
	if len(presentation) > 253 {
		return ErrInvalid
	}
	selectorLabels := strings.Count(selector, ".") + 1
	domainLabels := strings.Count(domain, ".") + 1
	if selectorLabels+domainLabels+1 > 127 {
		return ErrInvalid
	}
	return nil
}

// canonicalDNSName validates one bounded non-root ASCII DNS name.
func canonicalDNSName(value string) (string, error) {
	if value == "" || len(value) > 253 {
		return "", ErrInvalid
	}
	labels := strings.Split(value, ".")
	if len(labels) == 0 || len(labels) > 127 {
		return "", ErrInvalid
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 ||
			!dnsEdge(label[0]) || !dnsEdge(label[len(label)-1]) {
			return "", ErrInvalid
		}
		for index := 1; index < len(label)-1; index++ {
			if !dnsEdge(label[index]) && label[index] != '-' {
				return "", ErrInvalid
			}
		}
	}
	return strings.ToLower(value), nil
}

// identifierEdge reports whether a byte is a lowercase ASCII letter or digit.
func identifierEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// dnsEdge reports whether a byte is an ASCII letter or digit.
func dnsEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}
