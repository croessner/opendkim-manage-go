package dkim2store

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const purgePlanVersion = "opendkim-manage-dkim2-purge-v1"

// GenerationPurgePlan binds one fully verified old generation to a stable current pointer.
type GenerationPurgePlan struct {
	current    uint64
	generation uint64
	metadata   dkim2model.CandidateMetadata
	digest     [sha256.Size]byte
}

type purgePlanWire struct {
	Version         string `json:"version"`
	Current         uint64 `json:"current"`
	Generation      uint64 `json:"generation"`
	Schema          string `json:"schema"`
	State           string `json:"state"`
	WasActive       bool   `json:"was_active"`
	Operation       string `json:"operation"`
	Source          uint64 `json:"source"`
	CandidateDigest string `json:"candidate_digest"`
	PlanDigest      string `json:"plan_digest"`
}

// NewGenerationPurgePlan freezes one exact purge-eligible inventory row.
func NewGenerationPurgePlan(inventory GenerationInventory, generation uint64) (GenerationPurgePlan, error) {
	if inventory.Current == 0 || generation == 0 || generation >= inventory.Current {
		return GenerationPurgePlan{}, ErrConflict
	}
	for _, root := range inventory.Roots {
		if root.Number != generation {
			continue
		}
		if !root.Complete || root.Schema != dkim2model.SchemaVersionV3 ||
			root.State != dkim2model.DatasetStateCommitted || !root.WasActive ||
			root.Metadata.Generation() != generation {
			return GenerationPurgePlan{}, ErrConflict
		}
		plan := GenerationPurgePlan{current: inventory.Current, generation: generation, metadata: root.Metadata}
		plan.digest = purgePlanDigest(plan)
		return plan, nil
	}
	return GenerationPurgePlan{}, ErrConflict
}

// Current returns the current-generation fence sealed into the plan.
func (p GenerationPurgePlan) Current() uint64 { return p.current }

// Generation returns the exact target generation.
func (p GenerationPurgePlan) Generation() uint64 { return p.generation }

func (p GenerationPurgePlan) valid() bool {
	expected := purgePlanDigest(p)
	if expected == ([sha256.Size]byte{}) {
		return false
	}
	return p.current > p.generation && p.generation > 0 && p.metadata.Generation() == p.generation &&
		subtle.ConstantTimeCompare(p.digest[:], expected[:]) == 1
}

func (p GenerationPurgePlan) equal(other GenerationPurgePlan) bool {
	return p.valid() && other.valid() && p.current == other.current && p.generation == other.generation &&
		p.metadata.ExactEqual(other.metadata) && subtle.ConstantTimeCompare(p.digest[:], other.digest[:]) == 1
}

func purgePlanDigest(plan GenerationPurgePlan) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("OPENDKIM-MANAGE-DKIM2-PURGE-PLAN-V1\x00"))
	writePurgeUint64(hash, plan.current)
	writePurgeUint64(hash, plan.generation)
	writePurgeUint64(hash, plan.metadata.SourceGeneration())
	if err := plan.metadata.WithLDAPValues(func(operation string, candidate []byte) error {
		writePurgeBytes(hash, []byte(operation))
		writePurgeBytes(hash, candidate)
		return nil
	}); err != nil {
		return [sha256.Size]byte{}
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func writePurgeUint64(writer io.Writer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writePurgeBytes(writer io.Writer, value []byte) {
	writePurgeUint64(writer, uint64(len(value)))
	_, _ = writer.Write(value)
}

// MarshalGenerationPurgePlan returns one canonical key-free protected journal artifact.
func MarshalGenerationPurgePlan(plan GenerationPurgePlan) ([]byte, error) {
	if !plan.valid() {
		return nil, ErrMalformed
	}
	wire := purgePlanWire{Version: purgePlanVersion, Current: plan.current, Generation: plan.generation,
		Schema: dkim2model.SchemaVersionV3, State: string(dkim2model.DatasetStateCommitted), WasActive: true,
		Source: plan.metadata.SourceGeneration(), PlanDigest: hex.EncodeToString(plan.digest[:])}
	if err := plan.metadata.WithLDAPValues(func(operation string, digest []byte) error {
		wire.Operation = operation
		wire.CandidateDigest = hex.EncodeToString(digest)
		return nil
	}); err != nil {
		return nil, ErrMalformed
	}
	return json.Marshal(wire)
}

// ParseGenerationPurgePlan accepts only the exact canonical artifact grammar.
func ParseGenerationPurgePlan(document []byte, maximumBytes int) (GenerationPurgePlan, error) {
	if maximumBytes < 1 || len(document) == 0 || len(document) > maximumBytes {
		return GenerationPurgePlan{}, ErrMalformed
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire purgePlanWire
	if err := decoder.Decode(&wire); err != nil || decoder.More() || wire.Version != purgePlanVersion ||
		wire.Schema != dkim2model.SchemaVersionV3 || wire.State != string(dkim2model.DatasetStateCommitted) || !wire.WasActive {
		return GenerationPurgePlan{}, ErrMalformed
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, document) {
		return GenerationPurgePlan{}, ErrMalformed
	}
	candidate, err := hex.DecodeString(wire.CandidateDigest)
	if err != nil {
		return GenerationPurgePlan{}, ErrMalformed
	}
	defer clear(candidate)
	metadata, err := dkim2model.ParseCandidateMetadata(wire.Operation, wire.Source, wire.Generation, candidate)
	if err != nil {
		return GenerationPurgePlan{}, ErrMalformed
	}
	planDigest, err := hex.DecodeString(wire.PlanDigest)
	if err != nil || len(planDigest) != sha256.Size {
		return GenerationPurgePlan{}, ErrMalformed
	}
	defer clear(planDigest)
	plan := GenerationPurgePlan{current: wire.Current, generation: wire.Generation, metadata: metadata}
	copy(plan.digest[:], planDigest)
	if !plan.valid() {
		return GenerationPurgePlan{}, ErrConflict
	}
	return plan, nil
}

func (GenerationPurgePlan) String() string   { return "dkim2store.GenerationPurgePlan{redacted}" }
func (GenerationPurgePlan) GoString() string { return "dkim2store.GenerationPurgePlan{redacted}" }
func (GenerationPurgePlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2store.GenerationPurgePlan{redacted}")
}
func (GenerationPurgePlan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("use MarshalGenerationPurgePlan")
}
