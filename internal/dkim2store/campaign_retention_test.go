package dkim2store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

func TestLDAPRepositoryCampaignStagesV3AndMovesCurrentOnce(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	bootstrap := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
	defer func() { _ = bootstrap.Close() }()
	if err := repository.Publish(context.Background(), 0, bootstrap); err != nil {
		t.Fatal(err)
	}
	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = current.Close() }()
	candidate := successorGeneration(t, current, 2)
	defer func() { _ = candidate.Close() }()
	operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{2}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, 1, candidate)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := repository.StageCampaign(context.Background(), candidate, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prepared.Close() }()
	if prepared.ObservedCurrent() != 1 {
		t.Fatal("campaign staging moved current")
	}
	before := len(executor.modifies)
	if err := repository.CommitCampaignAndSwitch(context.Background(), prepared); err != nil {
		t.Fatalf("commit campaign: %v; modifies=%d current=%#v", err, len(executor.modifies), executor.entries[dnKey(repository.currentDN)])
	}
	if len(executor.modifies)-before != 2 {
		t.Fatalf("campaign activation modifies = %d, want commit and current without mutating v2", len(executor.modifies)-before)
	}
	final, err := repository.LoadPending(context.Background(), 2, 8)
	if err != nil || final.ObservedCurrent() != 2 {
		t.Fatalf("final campaign readback = %#v, %v", final, err)
	}
	_ = final.Close()
}

func TestLDAPRepositoryRetentionInventoriesSuffixAndDeletesLeafFirst(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	bootstrap := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = bootstrap.Close() }()
	if err := repository.Publish(context.Background(), 0, bootstrap); err != nil {
		t.Fatal(err)
	}
	for generation := uint64(2); generation <= 3; generation++ {
		current, err := repository.LoadCurrent(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		candidate := successorGeneration(t, current, generation)
		_ = current.Close()
		operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{byte(generation + 1)}, 16)))
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, generation-1, candidate)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := repository.StageCampaign(context.Background(), candidate, metadata)
		_ = candidate.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.CommitCampaignAndSwitch(context.Background(), prepared); err != nil {
			_ = prepared.Close()
			t.Fatal(err)
		}
		_ = prepared.Close()
	}
	// Legacy v2 is deliberately not deleted by the native v3 retention path.
	for key, entry := range executor.entries {
		if isAtOrBelow(entry.DN, repository.generationRoot(1)) {
			delete(executor.entries, key)
		}
	}
	inventory, err := repository.InventoryGenerations(context.Background())
	if err != nil || len(inventory.Roots) != 2 || inventory.Roots[0].Number != 2 {
		t.Fatalf("suffix inventory = %#v, %v", inventory, err)
	}
	plan, err := NewGenerationPurgePlan(inventory, 2)
	if err != nil {
		t.Fatal(err)
	}
	root := executor.entries[dnKey(repository.generationRoot(2))]
	setEntryAttribute(root, attributeSourceGeneration, []string{"999"})
	deletesBeforeSourceMismatch := len(executor.deletes)
	if err := repository.DeleteGeneration(context.Background(), plan); !errors.Is(err, ErrConflict) {
		t.Fatalf("source-mismatched purge error = %v, want conflict", err)
	}
	if len(executor.deletes) != deletesBeforeSourceMismatch {
		t.Fatal("source-mismatched purge deleted LDAP entries")
	}
	setEntryAttribute(root, attributeSourceGeneration, []string{"1"})
	beforeEntries := entriesBelow(executor.entries, repository.generationRoot(2))
	executor.failDeleteAt = 2
	executor.deleteError = errors.New("synthetic crash boundary")
	if err := repository.DeleteGeneration(context.Background(), plan); err == nil {
		t.Fatal("DeleteGeneration() reported success after a partial delete")
	}
	afterFailure := entriesBelow(executor.entries, repository.generationRoot(2))
	if afterFailure == 0 || afterFailure >= beforeEntries {
		t.Fatalf("partial delete entries = %d, want between 1 and %d", afterFailure, beforeEntries-1)
	}
	executor.failDeleteAt = 0
	if err := repository.DeleteGeneration(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(executor.deletes) == 0 || !sameDN(executor.deletes[len(executor.deletes)-1].DN, repository.generationRoot(2)) {
		t.Fatal("retention did not delete the generation root last")
	}
	final, err := repository.InventoryGenerations(context.Background())
	if err != nil || len(final.Roots) != 1 || final.Roots[0].Number != 3 || final.Current != 3 {
		t.Fatalf("post-delete inventory = %#v, %v", final, err)
	}
}

func entriesBelow(entries map[string]*ldap.Entry, base string) int {
	count := 0
	for _, entry := range entries {
		if isAtOrBelow(entry.DN, base) {
			count++
		}
	}
	return count
}
