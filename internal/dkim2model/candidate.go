package dkim2model

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	// SchemaVersionV3 is the public immutable-candidate LDAP contract.
	SchemaVersionV3 = "dkim2-datasource-v3"
	// CandidateDigestBytes is the exact SHA-256 value size stored in LDAP.
	CandidateDigestBytes          = sha256.Size
	campaignCandidateDigestDomain = "DKIM2-CAMPAIGN-CANDIDATE-CONTENT-V2\x00"
	candidateMetadataRedacted     = "dkim2model.CandidateMetadata{redacted}"
)

// CandidateMetadata binds one complete successor to its source, operation, and protected content digest.
type CandidateMetadata struct {
	operation  string
	source     uint64
	generation uint64
	digest     [sha256.Size]byte
}

// OperationID owns one canonical protected 128-bit campaign identity.
type OperationID struct{ value string }

// GenerateOperationID reads exactly 128 bits and returns their canonical lower-case base32 form.
func GenerateOperationID(random io.Reader) (OperationID, error) {
	if random == nil {
		return OperationID{}, ErrInvalid
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(random, raw); err != nil || allZero(raw) {
		clear(raw)
		return OperationID{}, errors.New("read protected DKIM2 operation identity")
	}
	value := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	clear(raw)
	if !validOperationID(value) {
		return OperationID{}, ErrInvalid
	}
	return OperationID{value: value}, nil
}

// WithValue supplies the protected operation ID only to an explicit persistence callback.
func (o OperationID) WithValue(use func(string) error) error {
	if use == nil || !validOperationID(o.value) {
		return ErrInvalid
	}
	if err := use(o.value); err != nil {
		return errors.New("use protected DKIM2 operation identity")
	}
	return nil
}
func (OperationID) String() string   { return "dkim2model.OperationID{redacted}" }
func (OperationID) GoString() string { return "dkim2model.OperationID{redacted}" }
func (OperationID) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2model.OperationID{redacted}")
}
func (OperationID) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// NewCandidateMetadataForOperation computes metadata from a typed protected operation identity.
func NewCandidateMetadataForOperation(operation OperationID, source uint64, candidate *Generation) (CandidateMetadata, error) {
	return NewCandidateMetadata(operation.value, source, candidate)
}

// ParseCandidateMetadata validates detached v3 LDAP metadata before candidate readback validation.
func ParseCandidateMetadata(operation string, source, generation uint64, digest []byte) (CandidateMetadata, error) {
	if !validOperationID(operation) || source == 0 || generation <= source || len(digest) != sha256.Size || allZero(digest) {
		return CandidateMetadata{}, ErrInvalid
	}
	var value [sha256.Size]byte
	copy(value[:], digest)
	return CandidateMetadata{operation: operation, source: source, generation: generation, digest: value}, nil
}

// ValidateCandidate recomputes and compares the complete protected candidate commitment.
func (m CandidateMetadata) ValidateCandidate(candidate *Generation) error {
	computed, err := NewCandidateMetadata(m.operation, m.source, candidate)
	if err != nil || computed.generation != m.generation || !m.DigestEqual(computed) {
		return ErrInvalid
	}
	return nil
}

// NewCandidateMetadata computes the public v3 candidate digest grammar without a foreign package dependency.
func NewCandidateMetadata(operation string, source uint64, candidate *Generation) (CandidateMetadata, error) {
	if !validOperationID(operation) || source == 0 || candidate == nil || candidate.Number() <= source ||
		candidate.State() != DatasetStateCommitted && candidate.State() != DatasetStateStaging {
		return CandidateMetadata{}, ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte(campaignCandidateDigestDomain))
	writeFramedString(h, SchemaVersionV3)
	writeUint64(h, source)
	writeUint64(h, candidate.Number())
	writeFramedString(h, operation)
	if err := writeCandidateGeneration(h, candidate); err != nil {
		return CandidateMetadata{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	if allZero(digest[:]) {
		return CandidateMetadata{}, ErrInvalid
	}
	return CandidateMetadata{operation: operation, source: source, generation: candidate.Number(), digest: digest}, nil
}

func validOperationID(value string) bool {
	if len(value) != 26 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value))
	if err != nil || len(decoded) != 16 || allZero(decoded) {
		clear(decoded)
		return false
	}
	canonical := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded))
	clear(decoded)
	return canonical == value
}

// SchemaVersion returns the exact public LDAP schema marker.
func (CandidateMetadata) SchemaVersion() string { return SchemaVersionV3 }

// SourceGeneration returns the exact complete source snapshot.
func (m CandidateMetadata) SourceGeneration() uint64 { return m.source }

// Generation returns the exact successor generation.
func (m CandidateMetadata) Generation() uint64 { return m.generation }

// DigestBytes returns a detached candidate digest for an explicit LDAP boundary.
func (m CandidateMetadata) DigestBytes() []byte { return bytes.Clone(m.digest[:]) }

// WithLDAPValues supplies protected metadata only to one explicit persistence callback.
func (m CandidateMetadata) WithLDAPValues(use func(operation string, digest []byte) error) error {
	if use == nil || !validOperationID(m.operation) || m.source == 0 || m.generation <= m.source || allZero(m.digest[:]) {
		return ErrInvalid
	}
	digest := bytes.Clone(m.digest[:])
	defer clear(digest)
	if err := use(m.operation, digest); err != nil {
		return errors.New("persist protected DKIM2 candidate metadata")
	}
	return nil
}

// DigestEqual compares two initialized protected commitments in constant time.
func (m CandidateMetadata) DigestEqual(other CandidateMetadata) bool {
	return !allZero(m.digest[:]) && !allZero(other.digest[:]) &&
		subtle.ConstantTimeCompare(m.digest[:], other.digest[:]) == 1
}

// ExactEqual compares every immutable campaign metadata field without exposing it.
func (m CandidateMetadata) ExactEqual(other CandidateMetadata) bool {
	return m.source == other.source && m.generation == other.generation && m.operation == other.operation &&
		m.DigestEqual(other)
}

func (CandidateMetadata) String() string   { return candidateMetadataRedacted }
func (CandidateMetadata) GoString() string { return candidateMetadataRedacted }
func (CandidateMetadata) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, candidateMetadataRedacted)
}
func (CandidateMetadata) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

func writeCandidateGeneration(output hash.Hash, generation *Generation) error {
	handles := generation.Handles()
	slices.SortFunc(handles, func(a, b Handle) int { return strings.Compare(a.ID(), b.ID()) })
	writeCount(output, len(handles))
	for _, row := range handles {
		writeFramedString(output, row.ID())
	}

	profiles := generation.Profiles()
	slices.SortFunc(profiles, func(a, b Profile) int { return strings.Compare(a.ID(), b.ID()) })
	writeCount(output, len(profiles))
	for _, row := range profiles {
		writeFramedString(output, row.ID())
		writeFramedString(output, row.SigningDomain())
		writeFramedString(output, string(row.Status()))
		before, after, present := row.ValidityWindow()
		if !present {
			writeNullable(output, "", false)
			writeNullable(output, "", false)
		} else {
			writeNullable(output, before.Format(time.RFC3339Nano), true)
			writeNullable(output, after.Format(time.RFC3339Nano), true)
		}
	}

	credentials := generation.Credentials()
	slices.SortFunc(credentials, func(a, b Credential) int {
		if c := strings.Compare(a.ProfileID(), b.ProfileID()); c != 0 {
			return c
		}
		return strings.Compare(string(a.Algorithm()), string(b.Algorithm()))
	})
	writeCount(output, len(credentials))
	for _, row := range credentials {
		writeFramedString(output, row.ProfileID())
		writeFramedString(output, string(row.Algorithm()))
		writeFramedString(output, row.Selector())
		public := row.PublicSPKIDER()
		writeFramedBytes(output, public)
		clear(public)
		writeFramedString(output, row.HandleID())
	}

	policies := generation.Policies()
	slices.SortFunc(policies, func(a, b Policy) int {
		return strings.Compare(policyKey(a.TenantID(), a.SigningDomain(), a.Use()), policyKey(b.TenantID(), b.SigningDomain(), b.Use()))
	})
	writeCount(output, len(policies))
	for _, row := range policies {
		writeFramedString(output, row.TenantID())
		writeFramedString(output, row.SigningDomain())
		writeFramedString(output, string(row.Use()))
		writeFramedString(output, row.ProfileID())
		writeFramedString(output, string(row.Status()))
		writeFramedString(output, string(row.Rollout()))
		writeFramedString(output, string(row.Compatibility()))
		writeNullable(output, row.FeedbackRouteID(), row.FeedbackRouteID() != "")
	}

	materials := generation.KeyMaterials()
	defer closeKeyMaterials(materials)
	slices.SortFunc(materials, func(a, b *KeyMaterial) int { return strings.Compare(a.HandleID(), b.HandleID()) })
	writeCount(output, len(materials))
	for _, row := range materials {
		writeFramedString(output, row.TenantID())
		writeFramedString(output, row.SigningDomain())
		writeFramedString(output, string(row.Use()))
		writeFramedString(output, row.HandleID())
		writeFramedString(output, string(row.Algorithm()))
		public := row.PublicSPKIDER()
		writeFramedBytes(output, public)
		clear(public)
		private := row.PrivatePKCS8DER()
		if len(private) == 0 {
			return ErrClosed
		}
		writeFramedBytes(output, private)
		clear(private)
	}
	return nil
}

func writeCount(output hash.Hash, count int) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(count))
	_, _ = output.Write(raw[:])
}
func writeUint64(output hash.Hash, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	_, _ = output.Write(raw[:])
}
func writeFramedString(output hash.Hash, value string) { writeFramedBytes(output, []byte(value)) }
func writeFramedBytes(output hash.Hash, value []byte) {
	writeCount(output, len(value))
	_, _ = output.Write(value)
}
func writeNullable(output hash.Hash, value string, present bool) {
	if !present {
		_, _ = output.Write([]byte{0})
		return
	}
	_, _ = output.Write([]byte{1})
	writeFramedString(output, value)
}
func allZero(value []byte) bool {
	var combined byte
	for _, octet := range value {
		combined |= octet
	}
	return combined == 0
}
