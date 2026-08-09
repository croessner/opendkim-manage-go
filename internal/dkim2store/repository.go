// Package dkim2store persists complete immutable DKIM2 datasource generations.
package dkim2store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const retainedHistoryRedacted = "dkim2store.RetainedHistory{redacted}"

var (
	// ErrUnavailable identifies an uncertain LDAP result without retaining backend details.
	ErrUnavailable = errors.New("DKIM2 LDAP repository unavailable")
	// ErrMalformed identifies an incomplete or ambiguous DKIM2 LDAP dataset.
	ErrMalformed = errors.New("DKIM2 LDAP dataset is malformed")
	// ErrConflict identifies a stale generation fence or concurrent publisher.
	ErrConflict = errors.New("DKIM2 LDAP generation conflict")
	// ErrOutcomeUncertain identifies a write whose authoritative result requires readback.
	ErrOutcomeUncertain = errors.New("DKIM2 LDAP mutation outcome is uncertain")
)

// GenerationRepository owns complete generation loads and atomic publication.
type GenerationRepository interface {
	LoadCurrent(context.Context) (*dkim2model.Generation, error)
	LoadRetainedHistory(context.Context, int) (RetainedHistory, error)
	Publish(context.Context, uint64, *dkim2model.Generation) error
}

// RotationReadRepository exposes only bounded authoritative recovery projections.
type RotationReadRepository interface {
	GenerationRepository
	LoadRetainedGeneration(context.Context, uint64, int) (*dkim2model.Generation, error)
	LoadGenerationCreatedAt(context.Context, uint64) (time.Time, error)
	LoadCurrentActivation(context.Context) (CurrentActivation, error)
}

// RotationRepository separates unreachable staging from forward activation.
type RotationRepository interface {
	RotationReadRepository
	Stage(context.Context, *dkim2model.Generation, int) (*PreparedGeneration, error)
	LoadPending(context.Context, uint64, int) (*PreparedGeneration, error)
	CommitAndSwitch(context.Context, uint64, int) error
}

// CampaignRepository owns autonomous operation-bound v3 campaign staging and retention.
type CampaignRepository interface {
	RotationRepository
	StageCampaign(context.Context, *dkim2model.Generation, dkim2model.CandidateMetadata) (*PreparedGeneration, error)
	CommitCampaignAndSwitch(context.Context, *PreparedGeneration) error
	InventoryGenerations(context.Context) (GenerationInventory, error)
	DeleteGeneration(context.Context, GenerationPurgePlan) error
}

const preparedGenerationRedacted = "dkim2store.PreparedGeneration{redacted}"

// PreparedGeneration owns one exact staged or committed-but-unreachable readback.
type PreparedGeneration struct {
	expectedCurrent uint64
	observedCurrent uint64
	candidate       *dkim2model.Generation
	metadata        *dkim2model.CandidateMetadata
}

// CampaignMetadata returns exact protected v3 metadata only for campaign candidates.
func (p *PreparedGeneration) CampaignMetadata() (dkim2model.CandidateMetadata, bool) {
	if p == nil || p.metadata == nil {
		return dkim2model.CandidateMetadata{}, false
	}
	return *p.metadata, true
}

func newPreparedGeneration(expected, observed uint64, candidate *dkim2model.Generation) (*PreparedGeneration, error) {
	if expected == 0 || observed == 0 || candidate == nil || candidate.Number() != expected+1 ||
		(observed != expected && observed != candidate.Number()) {
		if candidate != nil {
			_ = candidate.Close()
		}
		return nil, ErrMalformed
	}
	return &PreparedGeneration{expectedCurrent: expected, observedCurrent: observed, candidate: candidate}, nil
}

// NewPreparedGeneration constructs validated detached publication evidence for repository implementations.
func NewPreparedGeneration(expected, observed uint64, candidate *dkim2model.Generation) (*PreparedGeneration, error) {
	if candidate == nil {
		return nil, ErrMalformed
	}
	owned, err := candidate.Clone()
	if err != nil {
		return nil, ErrMalformed
	}
	return newPreparedGeneration(expected, observed, owned)
}

// NewCampaignPreparedGeneration constructs detached exact v3 evidence for repository implementations and tests.
func NewCampaignPreparedGeneration(
	expected, observed uint64,
	candidate *dkim2model.Generation,
	metadata dkim2model.CandidateMetadata,
) (*PreparedGeneration, error) {
	prepared, err := NewPreparedGeneration(expected, observed, candidate)
	if err != nil {
		return nil, err
	}
	owned, err := prepared.Generation()
	if err != nil || metadata.SourceGeneration() != expected || metadata.Generation() != prepared.CandidateNumber() ||
		metadata.ValidateCandidate(owned) != nil {
		if owned != nil {
			_ = owned.Close()
		}
		_ = prepared.Close()
		return nil, ErrMalformed
	}
	_ = owned.Close()
	prepared.metadata = &metadata
	return prepared, nil
}

func (p *PreparedGeneration) ExpectedCurrent() uint64 {
	if p == nil {
		return 0
	}
	return p.expectedCurrent
}

func (p *PreparedGeneration) ObservedCurrent() uint64 {
	if p == nil {
		return 0
	}
	return p.observedCurrent
}

func (p *PreparedGeneration) CandidateNumber() uint64 {
	if p == nil || p.candidate == nil {
		return 0
	}
	return p.candidate.Number()
}

// Generation returns a detached owner so callers cannot mutate repository evidence.
func (p *PreparedGeneration) Generation() (*dkim2model.Generation, error) {
	if p == nil || p.candidate == nil {
		return nil, ErrMalformed
	}
	return p.candidate.Clone()
}

func (p *PreparedGeneration) Close() error {
	if p == nil || p.candidate == nil {
		return nil
	}
	err := p.candidate.Close()
	p.candidate = nil
	p.expectedCurrent = 0
	p.observedCurrent = 0
	p.metadata = nil
	return err
}

// GenerationInventory is one complete, current-fenced bounded retention snapshot.
type GenerationInventory struct {
	Current uint64
	Roots   []GenerationInventoryRoot
}

// GenerationInventoryRoot contains only deletion-classification facts proven by full readback.
type GenerationInventoryRoot struct {
	Number    uint64
	Schema    string
	State     dkim2model.DatasetState
	WasActive bool
	Complete  bool
	Metadata  dkim2model.CandidateMetadata
}

func (*PreparedGeneration) String() string   { return preparedGenerationRedacted }
func (*PreparedGeneration) GoString() string { return preparedGenerationRedacted }
func (*PreparedGeneration) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, preparedGenerationRedacted)
}
func (*PreparedGeneration) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// GenerationRoot is one bounded immutable root fact without generation contents.
type GenerationRoot struct {
	Number uint64
	State  dkim2model.DatasetState
}

// RetainedHistory proves whether all roots and historical identifiers were observed.
type RetainedHistory struct {
	Roots     []GenerationRoot
	Complete  bool
	selectors map[string]struct{}
	handles   map[string]struct{}
	lineages  []publicLineage
	facts     []dkim2model.LineageFact
}

// NewRetainedHistoryWithLineage constructs detached complete history from validated model facts.
func NewRetainedHistoryWithLineage(roots []GenerationRoot, selectors, handles []string, lineage dkim2model.LineageHistory) (RetainedHistory, error) {
	if !lineage.Complete {
		return RetainedHistory{}, ErrMalformed
	}
	clone, err := lineage.Clone()
	if err != nil {
		return RetainedHistory{}, ErrMalformed
	}
	result := NewRetainedHistory(roots, true, selectors, handles)
	result.facts = clone.Facts
	return result, nil
}

type publicLineage struct {
	generation uint64
	created    string
	tenant     string
	domain     string
	use        dkim2model.ProfileUse
	profileID  string
	selector   string
	algorithm  dkim2model.Algorithm
	publicSPKI []byte
	handle     string
}

// NewRetainedHistory constructs a detached history result for repositories and tests.
func NewRetainedHistory(roots []GenerationRoot, complete bool, selectors, handles []string) RetainedHistory {
	result := RetainedHistory{Roots: append([]GenerationRoot(nil), roots...), Complete: complete,
		selectors: make(map[string]struct{}, len(selectors)), handles: make(map[string]struct{}, len(handles))}
	for _, value := range selectors {
		result.selectors[value] = struct{}{}
	}
	for _, value := range handles {
		result.handles[value] = struct{}{}
	}
	return result
}

// SelectorUsed reports exact occurrence only when the history result is complete.
func (h RetainedHistory) SelectorUsed(value string) (bool, error) {
	if !h.Complete {
		return false, ErrMalformed
	}
	_, found := h.selectors[value]
	return found, nil
}

// HandleUsed reports exact occurrence only when the history result is complete.
func (h RetainedHistory) HandleUsed(value string) (bool, error) {
	if !h.Complete {
		return false, ErrMalformed
	}
	_, found := h.handles[value]
	return found, nil
}

// LineageHistory returns detached, redacted model facts only for complete history.
func (h RetainedHistory) LineageHistory() (dkim2model.LineageHistory, error) {
	if !h.Complete {
		return dkim2model.LineageHistory{}, ErrMalformed
	}
	if h.facts != nil {
		return (dkim2model.LineageHistory{Complete: true, Facts: h.facts}).Clone()
	}
	facts := make([]dkim2model.LineageFact, 0, len(h.lineages))
	for _, lineage := range h.lineages {
		fact, err := dkim2model.NewLineageFact(
			lineage.generation, lineage.created, lineage.tenant, lineage.domain, lineage.use,
			lineage.selector, lineage.algorithm, lineage.publicSPKI, lineage.handle,
		)
		if err != nil {
			return dkim2model.LineageHistory{}, ErrMalformed
		}
		facts = append(facts, fact)
	}
	return dkim2model.LineageHistory{Complete: true, Facts: facts}, nil
}

func samePublicLineage(left, right publicLineage) bool {
	return left.tenant == right.tenant && left.domain == right.domain && left.use == right.use &&
		left.profileID == right.profileID && left.selector == right.selector &&
		left.algorithm == right.algorithm && bytes.Equal(left.publicSPKI, right.publicSPKI) &&
		left.handle == right.handle
}

// CurrentActivation is one exact pointer generation and canonical activation-time projection.
type CurrentActivation struct {
	Generation uint64
	ModifiedAt time.Time
}

func (RetainedHistory) String() string   { return retainedHistoryRedacted }
func (RetainedHistory) GoString() string { return retainedHistoryRedacted }
func (RetainedHistory) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, retainedHistoryRedacted)
}
func (RetainedHistory) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }
