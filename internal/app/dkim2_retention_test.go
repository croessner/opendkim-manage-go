package app

import (
	"context"
	"encoding/base32"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
)

func TestAutomaticRetentionUsesConfiguredMaximumAndRollbackReserve(t *testing.T) {
	journalDirectory := t.TempDir()
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := make([]dkim2store.GenerationInventoryRoot, 15)
	for index := range roots {
		number := uint64(index + 2)
		roots[index] = dkim2store.GenerationInventoryRoot{Number: number, Schema: dkim2model.SchemaVersionV3,
			State: dkim2model.DatasetStateCommitted, WasActive: true, Complete: true,
			Metadata: syntheticRetentionMetadata(t, number)}
	}
	inventory := &dkim2store.GenerationInventory{Current: 16, Roots: roots}
	repository := &fakeRotationRepository{inventoryOverride: inventory, retained: map[uint64]*dkim2model.Generation{}}
	manager := &DKIM2Manager{cfg: &config.Config{DKIM2: config.DKIM2Config{
		Retention: config.DKIM2RetentionConfig{Enabled: true, MaxGenerations: 12, MinRollbackGenerations: 2,
			MaxDeleteBatch: 4, JournalFile: journalDirectory + "/retention-plan.json", MaxJournalBytes: 4096},
	}}, campaignRepository: repository}
	if err := manager.applyAutomaticRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(repository.deleteCalls, []uint64{2, 3, 4}) || len(inventory.Roots) != 12 {
		t.Fatalf("deleted=%v retained=%d", repository.deleteCalls, len(inventory.Roots))
	}
}

func TestAutomaticRetentionRetainsLegacyOldestGeneration(t *testing.T) {
	journalDirectory := t.TempDir()
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	inventory := &dkim2store.GenerationInventory{Current: 3, Roots: []dkim2store.GenerationInventoryRoot{
		{Number: 1, Schema: dkim2model.SchemaVersion, State: dkim2model.DatasetStateCommitted, WasActive: true, Complete: true},
		{Number: 2, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted, WasActive: true, Complete: true},
		{Number: 3, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted, WasActive: true, Complete: true},
	}}
	repository := &fakeRotationRepository{inventoryOverride: inventory, retained: map[uint64]*dkim2model.Generation{}}
	manager := &DKIM2Manager{cfg: &config.Config{DKIM2: config.DKIM2Config{
		Retention: config.DKIM2RetentionConfig{Enabled: true, MaxGenerations: 2, MinRollbackGenerations: 1,
			MaxDeleteBatch: 1, JournalFile: journalDirectory + "/retention-plan.json", MaxJournalBytes: 4096},
	}}, campaignRepository: repository}
	if err := manager.applyAutomaticRetention(context.Background()); err == nil || len(repository.deleteCalls) != 0 {
		t.Fatalf("legacy retention err=%v deletes=%v", err, repository.deleteCalls)
	}
}

func TestAutomaticRetentionSkipsLegacyAndDeletesEligibleV3History(t *testing.T) {
	journalDirectory := t.TempDir()
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	inventory := &dkim2store.GenerationInventory{Current: 4, Roots: []dkim2store.GenerationInventoryRoot{
		{Number: 1, Schema: dkim2model.SchemaVersion, State: dkim2model.DatasetStateCommitted, Complete: true},
		{Number: 2, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 2)},
		{Number: 3, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 3)},
		{Number: 4, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 4)},
	}}
	repository := &fakeRotationRepository{inventoryOverride: inventory, retained: map[uint64]*dkim2model.Generation{}}
	manager := &DKIM2Manager{cfg: &config.Config{DKIM2: config.DKIM2Config{Retention: config.DKIM2RetentionConfig{
		Enabled: true, MaxGenerations: 2, MinRollbackGenerations: 0, MaxDeleteBatch: 2,
		JournalFile: journalDirectory + "/retention-plan.json", MaxJournalBytes: 4096,
	}}}, campaignRepository: repository}
	if err := manager.applyAutomaticRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(repository.deleteCalls, []uint64{2, 3}) || inventory.Roots[0].Number != 1 {
		t.Fatalf("deletes=%v roots=%v", repository.deleteCalls, inventory.Roots)
	}
}

func TestAutomaticRetentionResumesExactJournalAfterUncertainDelete(t *testing.T) {
	journalDirectory := t.TempDir()
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(journalDirectory, "retention-plan.json")
	inventory := &dkim2store.GenerationInventory{Current: 3, Roots: []dkim2store.GenerationInventoryRoot{
		{Number: 2, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 2)},
		{Number: 3, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 3)},
	}}
	repository := &fakeRotationRepository{inventoryOverride: inventory,
		retained: map[uint64]*dkim2model.Generation{}, deleteFailures: 1}
	manager := &DKIM2Manager{cfg: &config.Config{DKIM2: config.DKIM2Config{Retention: config.DKIM2RetentionConfig{
		Enabled: true, MaxGenerations: 1, MinRollbackGenerations: 0, MaxDeleteBatch: 1,
		JournalFile: journal, MaxJournalBytes: 4096,
	}}}, campaignRepository: repository}
	if err := manager.applyAutomaticRetention(context.Background()); err == nil {
		t.Fatal("uncertain delete reported retention success")
	}
	firstArtifact, err := os.ReadFile(journal)
	if err != nil {
		t.Fatalf("retained journal: %v", err)
	}
	if err := manager.applyAutomaticRetention(context.Background()); err != nil {
		t.Fatalf("retention resume: %v", err)
	}
	if _, err := os.Lstat(journal); !os.IsNotExist(err) {
		t.Fatalf("completed journal still present: %v", err)
	}
	if !slices.Equal(repository.deleteCalls, []uint64{2, 2}) || len(firstArtifact) == 0 {
		t.Fatalf("delete calls=%v artifact=%d", repository.deleteCalls, len(firstArtifact))
	}
	clear(firstArtifact)
}

func TestAutomaticDryRunIdleNeverCreatesJournalOrDeletes(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{
		Auto: true, UpdateDNS: true, DryRun: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.lineageCreatedAt = now.Add(-time.Hour)
	repository.inventoryOverride = &dkim2store.GenerationInventory{Current: 3, Roots: []dkim2store.GenerationInventoryRoot{
		{Number: 2, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 2)},
		{Number: 3, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
			WasActive: true, Complete: true, Metadata: syntheticRetentionMetadata(t, 3)},
	}}
	manager.cfg.DKIM2.Retention.MaxGenerations = 1
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeIdle || len(repository.deleteCalls) != 0 {
		t.Fatalf("dry-run result=%#v deletes=%v err=%v", result, repository.deleteCalls, err)
	}
	if _, err := os.Lstat(manager.cfg.DKIM2.Retention.JournalFile); !os.IsNotExist(err) {
		t.Fatalf("dry-run journal exists: %v", err)
	}
}

func syntheticRetentionMetadata(t *testing.T, generation uint64) dkim2model.CandidateMetadata {
	t.Helper()
	raw := make([]byte, 16)
	for index := range raw {
		raw[index] = byte(generation + uint64(index))
	}
	operation := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	digest := make([]byte, dkim2model.CandidateDigestBytes)
	for index := range digest {
		digest[index] = byte(generation + uint64(index) + 1)
	}
	metadata, err := dkim2model.ParseCandidateMetadata(operation, generation-1, generation, digest)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}
