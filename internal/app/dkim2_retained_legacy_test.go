package app

import (
	"context"
	"slices"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
)

// TestLegacyRetentionHistoryAllowsDryRunAndPreservesMutationFences exercises the real manager preflight after retention.
func TestLegacyRetentionHistoryAllowsDryRunAndPreservesMutationFences(t *testing.T) {
	first := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	defer func() { _ = first.Close() }()
	builder, err := first.NextBuilder(5, dkim2model.DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	current, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	history := publicHistoryForGeneration(current)
	history.Roots = []dkim2store.GenerationRoot{
		{Number: 1, Schema: dkim2model.SchemaVersion, State: dkim2model.DatasetStateCommitted},
		{Number: 4, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted},
		{Number: 5, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted},
	}
	repository.history = &history
	manager := testDKIM2Manager(repository, &cli.Options{
		Create: true, Domains: []string{"new.example.test"}, Selectors: []string{"fresh-selector"},
		KeyType: "ed25519", Size: 2048, DryRun: true,
	})
	if _, err := manager.Run(); err != nil || repository.publishes != 0 {
		t.Fatalf("dry-run after retention failed or wrote LDAP: %v", err)
	}
	if pending, err := exactPendingSuccessor(history, 5); err != nil || pending != 0 {
		t.Fatal("valid legacy plus current suffix was rejected")
	}
	original := slices.Clone(history.Roots)
	for _, test := range []struct {
		name   string
		change func(*dkim2store.RetainedHistory)
	}{
		{"missing-current", func(h *dkim2store.RetainedHistory) { h.Roots = h.Roots[:2] }},
		{"unknown-schema", func(h *dkim2store.RetainedHistory) { h.Roots[0].Schema = "" }},
		{"interior-gap", func(h *dkim2store.RetainedHistory) { h.Roots[1].Number = 3 }},
		{"duplicate", func(h *dkim2store.RetainedHistory) { h.Roots[1] = h.Roots[2] }},
		{"uncommitted-history", func(h *dkim2store.RetainedHistory) { h.Roots[0].State = dkim2model.DatasetStateStaging }},
		{"higher-root", func(h *dkim2store.RetainedHistory) {
			h.Roots = append(h.Roots, dkim2store.GenerationRoot{Number: 6, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateStaging})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			history.Roots = slices.Clone(original)
			test.change(&history)
			if _, err := manager.loadMutationHistory(context.Background(), current); err == nil {
				t.Fatal("ambiguous retained history passed mutation preflight")
			}
		})
	}
	history.Roots = append(slices.Clone(original), dkim2store.GenerationRoot{
		Number: 6, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateStaging,
	})
	if pending, err := exactPendingSuccessor(history, 5); err != nil || pending != 6 {
		t.Fatal("one exact current+1 candidate was rejected")
	}
	history.Roots = append(history.Roots, dkim2store.GenerationRoot{Number: 7, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateStaging})
	if _, err := exactPendingSuccessor(history, 5); err == nil {
		t.Fatal("current+2 candidate was accepted")
	}
}
