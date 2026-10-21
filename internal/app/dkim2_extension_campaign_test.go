package app

import (
	"slices"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// extensionCampaignGeneration returns three active bindings of every native
// use with mixed algorithm sets, none of them due for ordinary rotation.
func extensionCampaignGeneration(t *testing.T) *dkim2model.Generation {
	t.Helper()
	return rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "one.example", suffix: "origin", algorithms: []dkim2model.Algorithm{
			dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
		}},
		{domain: "one.example", suffix: "dsn", use: dkim2model.ProfileUseDeliveryStatus, algorithms: []dkim2model.Algorithm{
			dkim2model.AlgorithmEd25519SHA256,
		}},
		{domain: "transit.example", suffix: "transit", use: dkim2model.ProfileUseOrdinaryTransit, algorithms: []dkim2model.Algorithm{
			dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
		}},
	})
}

// newExtensionCampaignHarness configures one operator extension campaign
// whose bindings are all younger than the ordinary rotation interval.
func newExtensionCampaignHarness(t *testing.T, current *dkim2model.Generation, opts *cli.Options) (*DKIM2Manager, *fakeRotationRepository, *fakeRotationPublisher, *fakeRotationProof) {
	t.Helper()
	manager, repository, events := newRotationHarness(t, current, opts)
	manager.cfg.DKIM2.RotationEnabled = true
	manager.now = func() time.Time { return time.Date(2020, 1, 5, 0, 0, 0, 0, time.UTC) }
	publisher := &fakeRotationPublisher{events: events}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }
	return manager, repository, publisher, proof
}

// TestDKIM2AutoExtensionCampaignExtendsEveryBindingInOneGeneration proves
// that --auto --keytype all replaces every active binding, due or not, with
// fresh RSA, Ed25519, and composite keys in exactly one activated generation.
func TestDKIM2AutoExtensionCampaignExtendsEveryBindingInOneGeneration(t *testing.T) {
	current := extensionCampaignGeneration(t)
	manager, repository, publisher, _ := newExtensionCampaignHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "all"})
	defer repository.close()

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated {
		t.Fatalf("extension result=%#v err=%v", result, err)
	}
	if repository.stageCalls != 1 || repository.commitCalls != 1 || publisher.calls != 9 {
		t.Fatalf("stage=%d commit=%d publish=%d", repository.stageCalls, repository.commitCalls, publisher.calls)
	}
	if repository.pending.Number() != current.Number()+1 {
		t.Fatalf("candidate generation = %d", repository.pending.Number())
	}
	for _, profile := range repository.pending.Profiles() {
		credentials := credentialsForProfile(repository.pending, profile.ID())
		algorithms := make([]dkim2model.Algorithm, len(credentials))
		for index, credential := range credentials {
			algorithms[index] = credential.Algorithm()
			if _, reused := current.CredentialByDomainSelector(profile.SigningDomain(), credential.Selector()); reused {
				t.Fatal("extension campaign kept a source selector")
			}
		}
		slices.SortFunc(algorithms, dkim2model.CompareAlgorithms)
		if !slices.Equal(algorithms, dkim2model.SigningAlgorithms()) {
			t.Fatalf("%s algorithms = %v", profile.ID(), algorithms)
		}
	}
}

// TestDKIM2AutoWithoutKeyTypeKeepsSetsAndSkipsUndueBindings pins the daily
// campaign: without --keytype nothing young is rotated or extended.
func TestDKIM2AutoWithoutKeyTypeKeepsSetsAndSkipsUndueBindings(t *testing.T) {
	manager, repository, _, _ := newExtensionCampaignHarness(t, extensionCampaignGeneration(t),
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()

	result, err := manager.Run()
	if err != nil || repository.stageCalls != 0 || repository.pending != nil ||
		result.DKIM2Outcome != DKIM2OutcomeReconciled && result.DKIM2Outcome != DKIM2OutcomeIdle {
		t.Fatalf("daily result=%#v stage=%d err=%v", result, repository.stageCalls, err)
	}
}

// TestDKIM2AutoExtensionRefusesToShrinkBeforeMutation proves a requested set
// lacking any current algorithm fails closed before staging or DNS.
func TestDKIM2AutoExtensionRefusesToShrinkBeforeMutation(t *testing.T) {
	manager, repository, publisher, _ := newExtensionCampaignHarness(t, extensionCampaignGeneration(t),
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "composite"})
	defer repository.close()

	result, err := manager.Run()
	if err == nil || result != nil && result.DKIM2Outcome != "" || repository.stageCalls != 0 || publisher.calls != 0 {
		t.Fatalf("shrinking result=%#v stage=%d publish=%d err=%v", result, repository.stageCalls, publisher.calls, err)
	}
}

// TestDKIM2AutoExtensionRejectsExplicitScope keeps the campaign global.
func TestDKIM2AutoExtensionRejectsExplicitScope(t *testing.T) {
	manager, repository, _, _ := newExtensionCampaignHarness(t, extensionCampaignGeneration(t),
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "all", Domains: []string{"one.example"}})
	defer repository.close()

	if _, err := manager.Run(); err == nil || repository.stageCalls != 0 {
		t.Fatalf("scoped extension accepted, stage=%d", repository.stageCalls)
	}
}

// TestDKIM2AutoExtensionDryRunPerformsNoWrites proves dry-run plans the
// campaign without staging, DNS construction, or retention.
func TestDKIM2AutoExtensionDryRunPerformsNoWrites(t *testing.T) {
	manager, repository, _, _ := newExtensionCampaignHarness(t, extensionCampaignGeneration(t),
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "all", DryRun: true})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("dry-run opened DNS publisher")
		return nil, nil
	}

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun || repository.stageCalls != 0 ||
		repository.commitCalls != 0 || repository.pending != nil || len(repository.deleteCalls) != 0 {
		t.Fatalf("dry-run result=%#v stage=%d commit=%d deletes=%v err=%v",
			result, repository.stageCalls, repository.commitCalls, repository.deleteCalls, err)
	}
}

// TestDKIM2AutoExtensionIsIdleOnceEveryBindingIsExtended proves a repeated
// campaign does not rotate an already extended dataset again.
func TestDKIM2AutoExtensionIsIdleOnceEveryBindingIsExtended(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "one.example", suffix: "origin", algorithms: dkim2model.SigningAlgorithms()},
	})
	manager, repository, _, _ := newExtensionCampaignHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "all"})
	defer repository.close()

	result, err := manager.Run()
	if err != nil || repository.stageCalls != 0 || repository.pending != nil ||
		result.DKIM2Outcome != DKIM2OutcomeReconciled && result.DKIM2Outcome != DKIM2OutcomeIdle {
		t.Fatalf("repeated result=%#v stage=%d err=%v", result, repository.stageCalls, err)
	}
}

// TestDKIM2AutoExtensionResumesStoredCandidateAfterDNSFailure proves an
// interrupted campaign resumes the exact staged candidate without new keys,
// both with the same --keytype and through the daily --auto job.
func TestDKIM2AutoExtensionResumesStoredCandidateAfterDNSFailure(t *testing.T) {
	for _, keyType := range []string{"all", ""} {
		t.Run("keytype="+keyType, func(t *testing.T) {
			manager, repository, publisher, _ := newExtensionCampaignHarness(t, extensionCampaignGeneration(t),
				&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "all"})
			defer repository.close()
			publisher.failAt = 4
			if _, err := manager.Run(); err == nil || repository.stageCalls != 1 || repository.commitCalls != 0 {
				t.Fatalf("interrupted campaign stage=%d commit=%d err=%v", repository.stageCalls, repository.commitCalls, err)
			}
			staged, err := repository.pending.Clone()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = staged.Close() }()

			manager.opts.KeyType = keyType
			publisher.failAt = 0
			random := &forbiddenRandom{}
			manager.random = random
			result, err := manager.Run()
			if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || repository.stageCalls != 1 ||
				repository.commitCalls != 1 || random.reads != 0 {
				t.Fatalf("resume result=%#v stage=%d commit=%d random=%d err=%v",
					result, repository.stageCalls, repository.commitCalls, random.reads, err)
			}
			committed, err := generationWithState(staged, dkim2model.DatasetStateCommitted)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = committed.Close() }()
			if !repository.pending.Equivalent(committed) {
				t.Fatal("resume activated a different candidate")
			}
		})
	}
}

// TestDKIM2AutoExtensionResumeRejectsMismatchedStoredCandidate proves that
// --keytype never adopts a stored candidate with another algorithm set or
// one that leaves an active binding unrotated.
func TestDKIM2AutoExtensionResumeRejectsMismatchedStoredCandidate(t *testing.T) {
	for _, test := range []struct {
		name    string
		stage   string
		resume  string
		dueOnly bool
	}{
		{name: "different extension set", stage: "both", resume: "all"},
		{name: "ordinary due campaign", dueOnly: true, resume: "all"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := rotationGenerationBindings(t, []rotationBindingSpec{
				{domain: "one.example", suffix: "origin", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
				{domain: "two.example", suffix: "other", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
			})
			manager, repository, publisher, _ := newExtensionCampaignHarness(t, current,
				&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048, KeyType: test.stage})
			defer repository.close()
			if test.dueOnly {
				manager.now = func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }
			}
			publisher.failAt = 1
			if _, err := manager.Run(); err == nil || repository.stageCalls != 1 {
				t.Fatalf("fixture campaign was not interrupted, stage=%d err=%v", repository.stageCalls, err)
			}

			manager.opts.KeyType = test.resume
			publisher.failAt = 0
			publisher.calls = 0
			if _, err := manager.Run(); err == nil || repository.commitCalls != 0 || publisher.calls != 0 {
				t.Fatalf("mismatched resume commit=%d publish=%d err=%v", repository.commitCalls, publisher.calls, err)
			}
		})
	}
}
