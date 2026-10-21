package dkim2store

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// TestLDAPRepositoryRetentionPreservesLegacyAcrossRepeatedDeletes reproduces the retained legacy anchor after real repository purges.
func TestLDAPRepositoryRetentionPreservesLegacyAcrossRepeatedDeletes(t *testing.T) {
	repository, executor := retainedLegacyFixture(t, 5)
	legacyEntries := make(map[string]*ldap.Entry)
	for key, entry := range executor.entries {
		if isAtOrBelow(entry.DN, repository.generationRoot(1)) {
			legacyEntries[key] = cloneEntry(entry)
		}
	}
	for _, target := range []uint64{2, 3} {
		inventory, err := repository.InventoryGenerations(context.Background())
		if err != nil {
			t.Fatalf("inventory before deleting %d: %v", target, err)
		}
		plan, err := NewGenerationPurgePlan(inventory, target)
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.DeleteGeneration(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.InventoryGenerations(context.Background()); err != nil {
			t.Fatalf("retained legacy anchor blocks inventory after deleting %d: %v", target, err)
		}
		history, err := repository.LoadRetainedHistory(context.Background(), 8)
		if err != nil || !history.Complete || !historyHasExactCurrentMaximum(history.Roots, 5) {
			t.Fatalf("retained legacy anchor blocks history after deleting %d: %v", target, err)
		}
		for key, original := range legacyEntries {
			if !reflect.DeepEqual(executor.entries[key], original) {
				t.Fatal("retention changed protected legacy contents or metadata")
			}
		}
	}
	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = current.Close() }()
	if current.Number() != 5 {
		t.Fatal("retention changed current")
	}
	prepared := stageRetainedCampaign(t, repository, 6)
	defer func() { _ = prepared.Close() }()
	metadata, ok := prepared.CampaignMetadata()
	if !ok || metadata.SourceGeneration() != 5 || prepared.ExpectedCurrent() != 5 {
		t.Fatal("retention changed the next candidate's source-generation fence")
	}
	if err := repository.CommitCampaignAndSwitch(context.Background(), prepared); err != nil {
		t.Fatalf("publication after retained legacy gap: %v", err)
	}
}

// TestLegacyRetentionRejectsProtectedPlansAndMalformedRest preserves all original deletion fences.
func TestLegacyRetentionRejectsProtectedPlansAndMalformedRest(t *testing.T) {
	repository, executor := retainedLegacyFixture(t, 5)
	inventory, err := repository.InventoryGenerations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []uint64{0, 1, 5, 6} {
		if _, err := NewGenerationPurgePlan(inventory, number); err == nil {
			t.Fatal("current, legacy, absent, or zero target accepted")
		}
	}
	plan, err := NewGenerationPurgePlan(inventory, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ attribute, value string }{
		{attributeWasActive, "FALSE"}, {attributeSourceGeneration, "4"},
		{attributeCandidateDigest, string(bytes.Repeat([]byte{9}, 32))},
		{attributeOperationID, "aaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{attributeDatasetState, datasetStateStaging}, {attributeSchemaVersion, dkim2model.SchemaVersion},
	} {
		root := executor.entries[dnKey(repository.generationRoot(2))]
		original := cloneEntry(root)
		setEntryAttribute(root, change.attribute, []string{change.value})
		before := len(executor.deletes)
		if err := repository.DeleteGeneration(context.Background(), plan); err == nil || len(executor.deletes) != before {
			t.Fatalf("changed %s allowed a destructive request", change.attribute)
		}
		executor.entries[dnKey(original.DN)] = original
	}
	executor.failDeleteAt, executor.deleteError = 2, ErrUnavailable
	if err := repository.DeleteGeneration(context.Background(), plan); !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatal("partial-delete interruption was not retained")
	}
	extra := ldap.NewEntry("ou=unexpected,"+repository.generationRoot(2), map[string][]string{
		attributeObjectClass: {classTop, classOrganizationalUnit}, attributeOU: {"unexpected"},
	})
	executor.put(extra)
	executor.failDeleteAt = 0
	before := len(executor.deletes)
	if err := repository.DeleteGeneration(context.Background(), plan); !errors.Is(err, ErrConflict) || len(executor.deletes) != before {
		t.Fatal("malformed partial remainder allowed more deletion")
	}
}

// TestLegacyRetentionCurrentDriftStopsBeforeAnotherDelete covers both initial and in-flight fencing.
func TestLegacyRetentionCurrentDriftStopsBeforeAnotherDelete(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(strconv.FormatBool(during), func(t *testing.T) {
			reader, executor := retainedLegacyFixture(t, 5)
			inventory, err := reader.InventoryGenerations(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewGenerationPurgePlan(inventory, 2)
			if err != nil {
				t.Fatal(err)
			}
			writer := &currentDriftPurgeExecutor{fakeExecutor: executor, currentDN: reader.currentDN}
			repository, err := NewLDAPRepository(writer, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !during {
				setEntryAttribute(executor.entries[dnKey(reader.currentDN)], attributeGeneration, []string{"4"})
			}
			if err := repository.deleteGenerationFromPlan(context.Background(), plan, reader); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed current: %v", err)
			}
			wanted := 0
			if during {
				wanted = 1
			}
			if len(executor.deletes) != wanted {
				t.Fatal("a changed current allowed another destructive request")
			}
		})
	}
}

// currentDriftPurgeExecutor changes only the fake current pointer after the first committed delete.
type currentDriftPurgeExecutor struct {
	*fakeExecutor
	currentDN string
}

// DeleteRequest exposes a deterministic current-change boundary after one real fake-store deletion.
func (e *currentDriftPurgeExecutor) DeleteRequest(request *ldap.DelRequest) error {
	if err := e.fakeExecutor.DeleteRequest(request); err != nil {
		return err
	}
	setEntryAttribute(e.entries[dnKey(e.currentDN)], attributeGeneration, []string{"4"})
	return nil
}

// retainedLegacyFixture stages and activates native successors while preserving their complete v2 predecessor.
func retainedLegacyFixture(t *testing.T, last uint64) (*LDAPRepository, *fakeExecutor) {
	t.Helper()
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	bootstrap := fixedStoreGeneration(t, 1, dkim2model.DatasetStateStaging)
	defer func() { _ = bootstrap.Close() }()
	if err := repository.Publish(context.Background(), 0, bootstrap); err != nil {
		t.Fatal(err)
	}
	for number := uint64(2); number <= last; number++ {
		prepared := stageRetainedCampaign(t, repository, number)
		err := repository.CommitCampaignAndSwitch(context.Background(), prepared)
		_ = prepared.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return repository, executor
}

// stageRetainedCampaign prepares deterministic native test metadata without moving current.
func stageRetainedCampaign(t *testing.T, repository *LDAPRepository, number uint64) *PreparedGeneration {
	t.Helper()
	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	candidate := successorGeneration(t, current, number)
	_ = current.Close()
	defer func() { _ = candidate.Close() }()
	operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{byte(number)}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, number-1, candidate)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := repository.StageCampaign(context.Background(), candidate, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}
