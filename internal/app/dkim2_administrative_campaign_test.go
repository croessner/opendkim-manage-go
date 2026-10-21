package app

import (
	"context"
	"errors"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// TestDKIM2AdministrativeCreateUsesNativeCampaign keeps profile creation on the configured four-authority wire contract.
func TestDKIM2AdministrativeCreateUsesNativeCampaign(t *testing.T) {
	for _, dry := range []bool{true, false} {
		t.Run(map[bool]string{true: "dry-run", false: "publish"}[dry], func(t *testing.T) {
			manager, repository, _ := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
				&cli.Options{Create: true, Domains: []string{"example.test"}, KeyType: "ed25519", Size: 2048, Yes: true, DryRun: dry})
			defer repository.close()
			manager.cfg.DKIM2.RotationEnabled = true
			manager.cfg.DKIM2.ProfileUse = "ordinary_transit"
			if err := manager.create(context.Background()); err != nil {
				t.Fatal(err)
			}
			if dry {
				if repository.pending != nil {
					t.Fatal("dry-run staged a native candidate")
				}
				return
			}
			if repository.campaignMetadata == nil || repository.observed != repository.pending.Number() {
				t.Fatal("administrative profile bypassed the bound campaign/current path")
			}
			policy, found := exactPolicy(repository.pending, "tenant-test", "example.test", dkim2model.ProfileUseOrdinaryTransit)
			if !found || policy.Status() != dkim2model.RecordStatusDisabled {
				t.Fatal("new profile was not kept inactive")
			}
			before, _ := exactPolicy(repository.current, "tenant-test", "example.test", dkim2model.ProfileUseOriginator)
			if before.Status() != dkim2model.RecordStatusActive {
				t.Fatal("existing originator binding changed")
			}
		})
	}
}

// TestDKIM2AdministrativeCampaignUncertainReplies requires exact stage/current reconciliation.
func TestDKIM2AdministrativeCampaignUncertainReplies(t *testing.T) {
	for _, name := range []string{"lost-stage", "lost-activation", "commit-only", "stage-refused"} {
		t.Run(name, func(t *testing.T) {
			manager, repository, _ := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
				&cli.Options{Create: true, Domains: []string{"example.test"}, KeyType: "ed25519", Size: 2048, Yes: true})
			defer repository.close()
			manager.cfg.DKIM2.RotationEnabled, manager.cfg.DKIM2.ProfileUse = true, "ordinary_transit"
			repository.stageLost = name == "lost-stage"
			repository.activationLost = name == "lost-activation"
			repository.commitOnlyLost = name == "commit-only"
			if name == "stage-refused" {
				repository.fail["stage"] = errors.New("synthetic backend failure")
			}
			err := manager.create(context.Background())
			wantFailure := name == "commit-only" || name == "stage-refused"
			if (err != nil) != wantFailure {
				t.Fatalf("unexpected reconciliation result: %v", err)
			}
			if wantFailure && repository.observed != repository.current.Number() {
				t.Fatal("unproven outcome moved current")
			}
			if repository.stageCalls != 1 || repository.commitCalls > 1 {
				t.Fatal("reconciliation repeated a write")
			}
		})
	}
}

// TestDKIM2AdministrativeActivationPreservesDNSBarrier verifies native activation and a strict no-write dry-run.
func TestDKIM2AdministrativeActivationPreservesDNSBarrier(t *testing.T) {
	manager, repository, _ := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Create: true, Domains: []string{"example.test"}, KeyType: "ed25519", Size: 2048, Yes: true})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled, manager.cfg.DKIM2.ProfileUse = true, "ordinary_transit"
	if err := manager.create(context.Background()); err != nil {
		t.Fatal(err)
	}
	repository.retained[repository.current.Number()] = repository.current
	repository.current, repository.pending = repository.pending, nil
	policy, found := exactPolicy(repository.current, "tenant-test", "example.test", dkim2model.ProfileUseOrdinaryTransit)
	if !found {
		t.Fatal("new profile missing")
	}
	credentials := credentialsForProfile(repository.current, policy.ProfileID())
	if len(credentials) != 1 {
		t.Fatal("unexpected credential inventory")
	}
	manager.opts = &cli.Options{Active: true, Domains: []string{"example.test"}, Selectors: []string{credentials[0].Selector()}, Yes: true}
	manager.lookupTXT = func(string) ([]string, error) { return nil, errors.New("unavailable") }
	if err := manager.activate(context.Background()); err == nil || repository.stageCalls != 1 {
		t.Fatal("failed DNS proof wrote a generation")
	}
	manager.lookupTXT = func(string) ([]string, error) { return []string{dnsRecord(credentials[0])}, nil }
	manager.opts.DryRun = true
	if err := manager.activate(context.Background()); err != nil || repository.stageCalls != 1 {
		t.Fatal("dry-run changed native state", err)
	}
	manager.opts.DryRun = false
	if err := manager.activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, found := exactPolicy(repository.pending, "tenant-test", "example.test", dkim2model.ProfileUseOrdinaryTransit)
	if !found || active.Status() != dkim2model.RecordStatusActive || repository.observed != repository.pending.Number() || repository.campaignMetadata == nil {
		t.Fatal("profile activation did not use one complete native successor")
	}
}
