package dkim2store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

func TestRoleRepositorySeparatesCampaignAuthorities(t *testing.T) {
	seed := newFakeExecutor(testBaseDN)
	seedRepository := mustRepository(t, seed)
	bootstrap := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
	defer func() { _ = bootstrap.Close() }()
	if err := seedRepository.Publish(context.Background(), 0, bootstrap); err != nil {
		t.Fatal(err)
	}

	newRole := func() (*fakeExecutor, *LDAPRepository) {
		executor := newFakeExecutor(testBaseDN)
		executor.entries = seed.entries
		return executor, mustRepository(t, executor)
	}
	snapshotExecutor, snapshot := newRole()
	stagingExecutor, staging := newRole()
	activationExecutor, activation := newRole()
	purgeExecutor, purge := newRole()
	repository, err := NewRoleRepository(snapshot, staging, activation, purge)
	if err != nil {
		t.Fatal(err)
	}

	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	candidate := successorGeneration(t, current, 2)
	_ = current.Close()
	defer func() { _ = candidate.Close() }()
	operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{7}, 16)))
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
	if err := repository.CommitCampaignAndSwitch(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}

	if len(snapshotExecutor.adds) != 0 || len(snapshotExecutor.modifies) != 0 || len(snapshotExecutor.deletes) != 0 {
		t.Fatal("snapshot authority performed a lifecycle write")
	}
	if len(stagingExecutor.adds) == 0 || len(stagingExecutor.modifies) != 1 || len(stagingExecutor.deletes) != 0 {
		t.Fatalf("staging writes: adds=%d modifies=%d deletes=%d", len(stagingExecutor.adds), len(stagingExecutor.modifies), len(stagingExecutor.deletes))
	}
	if len(activationExecutor.adds) != 0 || len(activationExecutor.modifies) != 1 || len(activationExecutor.deletes) != 0 {
		t.Fatalf("activation writes: adds=%d modifies=%d deletes=%d", len(activationExecutor.adds), len(activationExecutor.modifies), len(activationExecutor.deletes))
	}
	if len(purgeExecutor.adds) != 0 || len(purgeExecutor.modifies) != 0 || len(purgeExecutor.deletes) != 0 {
		t.Fatal("purge authority wrote outside retention")
	}
}

func TestRoleRepositoryPurgeReadsOnlyThroughSnapshotAuthority(t *testing.T) {
	seed := newFakeExecutor(testBaseDN)
	seedRepository := mustRepository(t, seed)
	bootstrap := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = bootstrap.Close() }()
	if err := seedRepository.Publish(context.Background(), 0, bootstrap); err != nil {
		t.Fatal(err)
	}
	newRole := func() (*fakeExecutor, *LDAPRepository) {
		executor := newFakeExecutor(testBaseDN)
		executor.entries = seed.entries
		return executor, mustRepository(t, executor)
	}
	_, snapshot := newRole()
	_, staging := newRole()
	_, activation := newRole()
	purgeExecutor, purge := newRole()
	repository, err := NewRoleRepository(snapshot, staging, activation, purge)
	if err != nil {
		t.Fatal(err)
	}
	for number := uint64(2); number <= 3; number++ {
		current, err := repository.LoadCurrent(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		candidate := successorGeneration(t, current, number)
		_ = current.Close()
		operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{byte(number + 10)}, 16)))
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, number-1, candidate)
		if err != nil {
			_ = candidate.Close()
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
	inventory, err := repository.InventoryGenerations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGenerationPurgePlan(inventory, 2)
	if err != nil {
		t.Fatal(err)
	}
	purgeExecutor.mutateSearch = func(*ldap.SearchRequest, *ldap.SearchResult) error {
		return errors.New("purge authority attempted a forbidden read")
	}
	if err := repository.DeleteGeneration(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(purgeExecutor.searches) != 0 || len(purgeExecutor.deletes) == 0 {
		t.Fatalf("purge authority searches=%d deletes=%d", len(purgeExecutor.searches), len(purgeExecutor.deletes))
	}
}
