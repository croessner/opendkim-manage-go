package dkim2store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/go-ldap/ldap/v3"
)

func TestClassifyWriteErrorSeparatesConflictAndUncertainOutcome(t *testing.T) {
	if err := classifyWriteError(nil); err != nil {
		t.Fatalf("nil = %v", err)
	}
	assertion := ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("backend marker"))
	if err := classifyWriteError(assertion); !errors.Is(err, ErrConflict) || strings.Contains(err.Error(), "marker") {
		t.Fatalf("assertion = %v", err)
	}
	if err := classifyWriteError(errors.New("backend marker")); !errors.Is(err, ErrOutcomeUncertain) || strings.Contains(err.Error(), "marker") {
		t.Fatalf("transport = %v", err)
	}
}

func TestClassifyRecoveryFacts(t *testing.T) {
	tests := []struct {
		name  string
		facts RecoveryFacts
		want  RecoveryDecision
	}{
		{"new", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: false, HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryStageNew},
		{"staging", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: dkim2model.DatasetStateStaging, HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryResumeStaging},
		{"committed", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: dkim2model.DatasetStateCommitted, HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryResumeCommittedPointer},
		{"activated", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: dkim2model.DatasetStateCommitted, HistoryComplete: true, CurrentPresent: true, Current: 2, OutcomeCertain: true}, RecoveryAlreadyActivated},
		{"uncertain", RecoveryFacts{ExpectedBase: 1, Candidate: 2, HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: false}, RecoveryUncertain},
		{"partial", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: false, HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryRepairRequired},
		{"multiple", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: dkim2model.DatasetStateStaging, HistoryComplete: true, MultipleCandidates: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryRepairRequired},
		{"incomplete history", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: dkim2model.DatasetStateStaging, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryRepairRequired},
		{"wrong current", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: dkim2model.DatasetStateStaging, HistoryComplete: true, CurrentPresent: true, Current: 3, OutcomeCertain: true}, RecoveryConflict},
		{"noncontiguous", RecoveryFacts{ExpectedBase: 1, Candidate: 3, HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryConflict},
		{"overflow", RecoveryFacts{ExpectedBase: ^uint64(0), Candidate: 1, HistoryComplete: true, CurrentPresent: true, Current: ^uint64(0), OutcomeCertain: true}, RecoveryConflict},
		{"missing current", RecoveryFacts{ExpectedBase: 1, Candidate: 2, HistoryComplete: true, OutcomeCertain: true}, RecoveryConflict},
		{"invalid state", RecoveryFacts{ExpectedBase: 1, Candidate: 2, CandidatePresent: true, CandidateComplete: true, CandidateState: "other", HistoryComplete: true, CurrentPresent: true, Current: 1, OutcomeCertain: true}, RecoveryRepairRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyRecovery(test.facts); got != test.want {
				t.Fatalf("ClassifyRecovery() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRecoveryFactsAndDecisionFormattingAreClosed(t *testing.T) {
	facts := RecoveryFacts{ExpectedBase: 41, Candidate: 42, CandidatePresent: true, CandidateComplete: true,
		CandidateState: dkim2model.DatasetStateStaging, HistoryComplete: true, CurrentPresent: true, Current: 41, OutcomeCertain: true}
	for _, value := range []any{facts, &facts} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, value); got != "dkim2store.RecoveryFacts{redacted}" {
				t.Fatalf("format %s = %q", format, got)
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatalf("JSON = %s, %v", encoded, err)
		}
	}
	if got := fmt.Sprintf("%v", RecoveryResumeStaging); got != "resume-staging" {
		t.Fatalf("decision format = %q", got)
	}
}
