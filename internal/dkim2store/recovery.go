package dkim2store

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const recoveryFactsRedacted = "dkim2store.RecoveryFacts{redacted}"

// RecoveryDecision is one closed, side-effect-free lifecycle classification.
type RecoveryDecision string

const (
	RecoveryStageNew               RecoveryDecision = "stage-new"
	RecoveryResumeStaging          RecoveryDecision = "resume-staging"
	RecoveryResumeCommittedPointer RecoveryDecision = "resume-committed-pointer"
	RecoveryAlreadyActivated       RecoveryDecision = "already-activated"
	RecoveryConflict               RecoveryDecision = "conflict"
	RecoveryUncertain              RecoveryDecision = "uncertain"
	RecoveryRepairRequired         RecoveryDecision = "repair-required"
)

// RecoveryFacts contains only bounded generation and certainty facts.
type RecoveryFacts struct {
	ExpectedBase       uint64
	Candidate          uint64
	CandidatePresent   bool
	CandidateComplete  bool
	CandidateState     dkim2model.DatasetState
	HistoryComplete    bool
	MultipleCandidates bool
	CurrentPresent     bool
	Current            uint64
	OutcomeCertain     bool
}

// ClassifyRecovery derives the only safe next phase without performing I/O.
func ClassifyRecovery(f RecoveryFacts) RecoveryDecision {
	if f.ExpectedBase == ^uint64(0) || f.Candidate == 0 || f.Candidate != f.ExpectedBase+1 {
		return RecoveryConflict
	}
	if !f.HistoryComplete || f.MultipleCandidates {
		return RecoveryRepairRequired
	}
	if !f.OutcomeCertain {
		return RecoveryUncertain
	}
	if !f.CurrentPresent || f.Current != f.ExpectedBase && f.Current != f.Candidate {
		return RecoveryConflict
	}
	if !f.CandidatePresent {
		if f.Current == f.Candidate {
			return RecoveryRepairRequired
		}
		return RecoveryStageNew
	}
	if !f.CandidateComplete || f.CandidateState != dkim2model.DatasetStateStaging &&
		f.CandidateState != dkim2model.DatasetStateCommitted {
		return RecoveryRepairRequired
	}
	if f.CandidateState == dkim2model.DatasetStateStaging {
		if f.Current == f.Candidate {
			return RecoveryRepairRequired
		}
		return RecoveryResumeStaging
	}
	if f.Current == f.Candidate {
		return RecoveryAlreadyActivated
	}
	return RecoveryResumeCommittedPointer
}

func (RecoveryFacts) String() string   { return recoveryFactsRedacted }
func (RecoveryFacts) GoString() string { return recoveryFactsRedacted }
func (RecoveryFacts) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, recoveryFactsRedacted)
}
func (RecoveryFacts) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// String returns the closed operator-safe recovery state.
func (d RecoveryDecision) String() string { return string(d) }
