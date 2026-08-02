package dkim2store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

func TestLDAPRepositoryStageLeavesCurrentUnchangedAndLoadsExactPendingMaterial(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	second := successorGeneration(t, first, 2)
	defer func() { _ = second.Close() }()

	prepared, err := repository.Stage(context.Background(), second, 8)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if prepared.ExpectedCurrent() != 1 || prepared.ObservedCurrent() != 1 || prepared.CandidateNumber() != 2 {
		t.Fatalf("unexpected prepared facts: %v", prepared)
	}
	pointer := executor.entries[dnKey("cn=current,"+testBaseDN)]
	if got := pointer.GetAttributeValue(attributeGeneration); got != "1" {
		t.Fatalf("Stage() moved current to %q", got)
	}
	root := executor.entries[dnKey(repository.generationRoot(2))]
	if got := root.GetAttributeValue(attributeDatasetState); got != datasetStateStaging {
		t.Fatalf("staged root state = %q", got)
	}
	loaded, err := prepared.Generation()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	if !second.Equivalent(loaded) {
		t.Fatal("staged readback did not preserve exact candidate material")
	}
}

func TestLDAPRepositoryCommitAndSwitchUsesCriticalRootAndPointerAssertions(t *testing.T) {
	executor, repository, candidate := stagedSuccessor(t)
	defer func() { _ = candidate.Close() }()
	baseline := len(executor.modifies)
	if err := repository.CommitAndSwitch(context.Background(), 2, 8); err != nil {
		t.Fatalf("CommitAndSwitch() error = %v", err)
	}
	if len(executor.modifies) != baseline+2 {
		t.Fatalf("modify count = %d, want %d", len(executor.modifies), baseline+2)
	}
	for index, request := range executor.modifies[baseline:] {
		if len(request.Controls) != 1 {
			t.Fatalf("modify %d has no assertion control", index)
		}
		control, ok := request.Controls[0].(*ldap.ControlString)
		if !ok || control.ControlType != assertionControlOID || !control.Criticality || control.ControlValue == "" {
			t.Fatalf("modify %d assertion is not critical RFC 4528: %#v", index, request.Controls[0])
		}
	}
}

func TestLDAPRepositoryCommitClassifiesAssertionAndLostResponsesWithoutPointerRetry(t *testing.T) {
	for _, test := range []struct {
		name    string
		apply   bool
		failure error
		want    error
	}{
		{"not-applied", false, errors.New("backend marker"), ErrOutcomeUncertain},
		{"applied-response-lost", true, errors.New("backend marker"), ErrOutcomeUncertain},
		{"assertion-conflict", false, ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("backend marker")), ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, repository, candidate := stagedSuccessor(t)
			defer func() {
				if err := candidate.Close(); err != nil {
					t.Errorf("Close() = %v", err)
				}
			}()
			executor.failModifyAt = len(executor.modifies) + 1
			executor.modifyError = test.failure
			executor.applyModifyOnFailure = test.apply
			baseline := len(executor.modifies)
			err := repository.CommitAndSwitch(context.Background(), 2, 8)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "marker") {
				t.Fatalf("error = %v", err)
			}
			if len(executor.modifies) != baseline+1 {
				t.Fatalf("blind retry/pointer write count = %d", len(executor.modifies)-baseline)
			}
			if got := executor.entries[dnKey("cn=current,"+testBaseDN)].GetAttributeValue(attributeGeneration); got != "1" {
				t.Fatalf("current moved to %q", got)
			}
		})
	}
}

func TestLDAPRepositoryPointerLostResponseUsesReadbackWithoutRetry(t *testing.T) {
	executor, repository, candidate := stagedSuccessor(t)
	defer func() {
		if err := candidate.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	}()
	baseline := len(executor.modifies)
	executor.failModifyAt = baseline + 2
	executor.modifyError = errors.New("backend marker")
	executor.applyModifyOnFailure = true
	if err := repository.CommitAndSwitch(context.Background(), 2, 8); err != nil {
		t.Fatalf("CommitAndSwitch() = %v", err)
	}
	if len(executor.modifies) != baseline+2 {
		t.Fatalf("blind retry count = %d", len(executor.modifies)-baseline)
	}
	if got := executor.entries[dnKey("cn=current,"+testBaseDN)].GetAttributeValue(attributeGeneration); got != "2" {
		t.Fatalf("current = %q", got)
	}
}

func TestLDAPRepositoryPostWriteNilOrReferralResultIsOutcomeUncertain(t *testing.T) {
	for _, referral := range []bool{false, true} {
		t.Run(fmt.Sprintf("referral-%t", referral), func(t *testing.T) {
			executor, repository, candidate := stagedSuccessor(t)
			defer func() {
				if err := candidate.Close(); err != nil {
					t.Errorf("Close() = %v", err)
				}
			}()
			next := len(executor.modifies) + 1
			if referral {
				executor.referralResultAt = next
			} else {
				executor.nilModifyResultAt = next
			}
			err := repository.CommitAndSwitch(context.Background(), 2, 8)
			if !errors.Is(err, ErrOutcomeUncertain) {
				t.Fatalf("error = %v", err)
			}
			if got := executor.entries[dnKey("cn=current,"+testBaseDN)].GetAttributeValue(attributeGeneration); got != "1" {
				t.Fatalf("current = %q", got)
			}
		})
	}
}

func TestLDAPRepositoryLoadPendingDerivesBaseAndRejectsPointerRollback(t *testing.T) {
	executor, repository, candidate := stagedSuccessor(t)
	defer func() { _ = candidate.Close() }()
	prepared, err := repository.LoadPending(context.Background(), 2, 8)
	if err != nil {
		t.Fatalf("LoadPending() error = %v", err)
	}
	if prepared.ExpectedCurrent() != 1 {
		t.Fatalf("derived base = %d, want 1", prepared.ExpectedCurrent())
	}
	_ = prepared.Close()

	setEntryAttribute(executor.entries[dnKey("cn=current,"+testBaseDN)], attributeGeneration, []string{"3"})
	before := len(executor.modifies)
	if _, err := repository.LoadPending(context.Background(), 2, 8); !errors.Is(err, ErrConflict) {
		t.Fatalf("LoadPending() pointer conflict = %v", err)
	}
	if err := repository.CommitAndSwitch(context.Background(), 2, 8); !errors.Is(err, ErrConflict) {
		t.Fatalf("CommitAndSwitch() pointer conflict = %v", err)
	}
	if len(executor.modifies) != before {
		t.Fatal("pointer conflict performed a write")
	}
}

func TestLDAPRepositoryHistoryAllowsIdenticalLineageAndRejectsConflictingReuse(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	second := successorGeneration(t, first, 2)
	defer func() { _ = second.Close() }()
	if err := repository.Publish(context.Background(), 1, second); err != nil {
		t.Fatal(err)
	}
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil {
		t.Fatalf("identical lineage across G1/G2 error = %v", err)
	}
	lineage, err := history.LineageHistory()
	if err != nil || len(lineage.Facts) != 2 {
		t.Fatalf("lineage facts = %d, %v", len(lineage.Facts), err)
	}

	for _, entry := range executor.entries {
		if strings.Contains(entry.DN, "dkim2Generation=2") && hasObjectClass(entry, classCredential) {
			setEntryAttribute(entry, attributeAlgorithm, []string{string(dkim2model.AlgorithmRSASHA256)})
			break
		}
	}
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("conflicting historical selector reuse error = %v", err)
	}
}

func TestLDAPRepositoryHistoryNeverRequestsHistoricalPrivateMaterial(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	searchStart := len(executor.searches)
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	for _, request := range executor.searches[searchStart:] {
		for _, attribute := range request.Attributes {
			if strings.EqualFold(attribute, attributePrivatePKCS8) || attribute == "*" || attribute == "+" {
				t.Fatalf("history requested forbidden attribute %q", attribute)
			}
		}
	}
}

func TestLDAPRepositoryOperationalTimesUseExactCanonicalProjections(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	created, err := repository.LoadGenerationCreatedAt(context.Background(), 1)
	if err != nil || created.Format(generalizedTimeLayout) != "20250701000000Z" {
		t.Fatalf("created projection = %v, %v", created, err)
	}
	activation, err := repository.LoadCurrentActivation(context.Background())
	if err != nil || activation.Generation != 1 || activation.ModifiedAt.IsZero() {
		t.Fatalf("activation projection = %#v, %v", activation, err)
	}

	root := executor.entries[dnKey(repository.generationRoot(1))]
	setEntryAttribute(root, attributeCreateTimestamp, []string{"20250701000000.0Z"})
	if _, err := repository.LoadGenerationCreatedAt(context.Background(), 1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("fractional generalized time error = %v", err)
	}
	for _, request := range executor.searches {
		if sameDN(request.BaseDN, repository.generationRoot(1)) && len(request.Attributes) == 1 &&
			request.Attributes[0] == attributeCreateTimestamp {
			return
		}
	}
	t.Fatal("createTimestamp was not requested as a separate exact projection")
}

func TestLDAPRepositoryRetainedGenerationRejectsStagingAndReturnsDetachedCommitted(t *testing.T) {
	_, repository, candidate := stagedSuccessor(t)
	defer func() { _ = candidate.Close() }()
	if _, err := repository.LoadRetainedGeneration(context.Background(), 2, 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("staging retained generation error = %v", err)
	}
	if err := repository.CommitAndSwitch(context.Background(), 2, 8); err != nil {
		t.Fatal(err)
	}
	retained, err := repository.LoadRetainedGeneration(context.Background(), 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retained.Close() }()
	if retained.Number() != 1 || retained.State() != dkim2model.DatasetStateCommitted {
		t.Fatalf("retained generation = %v", retained)
	}
}

func stagedSuccessor(t *testing.T) (*fakeExecutor, *LDAPRepository, *dkim2model.Generation) {
	t.Helper()
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	second := successorGeneration(t, first, 2)
	_ = first.Close()
	prepared, err := repository.Stage(context.Background(), second, 8)
	if err != nil {
		_ = second.Close()
		t.Fatal(err)
	}
	_ = prepared.Close()
	return executor, repository, second
}

func successorGeneration(t *testing.T, current *dkim2model.Generation, number uint64) *dkim2model.Generation {
	t.Helper()
	builder, err := current.NextBuilder(number, dkim2model.DatasetStateStaging)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	candidate, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestParseGeneralizedTimeRejectsNonCanonicalForms(t *testing.T) {
	for _, value := range []string{"", "20250701000000.0Z", "20250701000000+0000", "20250230000000Z"} {
		if parsed, err := parseGeneralizedTime([]byte(value)); err == nil || !parsed.Equal(time.Time{}) {
			t.Fatalf("parseGeneralizedTime(%q) = %v, %v", value, parsed, err)
		}
	}
}
