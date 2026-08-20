package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

type fakeDualObserver struct {
	observations []dnsupdate.PresenceObservation
	calls        int
}

type cancelYesReader struct{ cancel context.CancelFunc }

func (r cancelYesReader) Read(buffer []byte) (int, error) {
	r.cancel()
	return copy(buffer, "yes\n"), nil
}

func (f *fakeDualObserver) ObserveChannels(context.Context, dnsupdate.ExpectedTXT) (dnsupdate.PresenceObservation, error) {
	if f.calls >= len(f.observations) {
		return dnsupdate.PresenceObservation{}, errors.New("unexpected dual observation")
	}
	observation := f.observations[f.calls]
	f.calls++
	return observation, nil
}

type fakeLifecycleRetirer struct {
	states      []dnsupdate.PresenceState
	observeCall int
	deleteCall  int
	deleteError error
}

func (f *fakeLifecycleRetirer) Observe(context.Context, dnsupdate.ExpectedTXT) (dnsupdate.PresenceState, error) {
	if f.observeCall >= len(f.states) {
		return dnsupdate.PresenceUncertain, errors.New("unexpected observation")
	}
	state := f.states[f.observeCall]
	f.observeCall++
	return state, nil
}

func (f *fakeLifecycleRetirer) DeleteExact(context.Context, string, dnsupdate.ExpectedTXT) (dnsupdate.DeleteResult, error) {
	f.deleteCall++
	if f.deleteError != nil {
		return dnsupdate.DeleteResumable, f.deleteError
	}
	return dnsupdate.DeleteRemoved, nil
}

func TestDKIM2AutoResumesExactPendingCandidateBeforeEligibilityOrRandomness(t *testing.T) {
	current, candidate := rotationSuccessorPair(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	})
	manager, repository, events := newRotationHarness(t, current, &cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	repository.pending, repository.observed = candidate, current.Number()
	operation, operationErr := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
	metadata, metadataErr := dkim2model.NewCandidateMetadataForOperation(operation, current.Number(), candidate)
	if operationErr != nil || metadataErr != nil {
		t.Fatal(errors.Join(operationErr, metadataErr))
	}
	repository.campaignMetadata = &metadata
	manager.cfg.DKIM2.RotationEnabled = true
	random := &forbiddenRandom{}
	manager.random = random
	publisher := &fakeRotationPublisher{events: events}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated {
		t.Fatalf("automatic resume result=%#v err=%v", result, err)
	}
	if random.reads != 0 || repository.stageCalls != 0 || publisher.calls != 2 || proof.calls != 2 {
		t.Fatalf("random=%d stage=%d publish=%d proof=%d", random.reads, repository.stageCalls, publisher.calls, proof.calls)
	}
}

func TestDKIM2AutomaticPendingDryRunPerformsNoDNSOrLDAPMutation(t *testing.T) {
	current, candidate := rotationSuccessorPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{
		Auto: true, UpdateDNS: true, DryRun: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.pending, repository.observed = candidate, current.Number()
	operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{3}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, current.Number(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	repository.campaignMetadata = &metadata
	manager.cfg.DKIM2.RotationEnabled = true
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("dry-run opened DNS publisher")
		return nil, errors.New("unreachable")
	}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun || repository.commitCalls != 0 || len(repository.deleteCalls) != 0 {
		t.Fatalf("result=%#v commits=%d deletes=%v err=%v", result, repository.commitCalls, repository.deleteCalls, err)
	}
}

func TestDKIM2AutoReconcilesAllCurrentDNSWithoutCreatingGeneration(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "dual", algorithms: []dkim2model.Algorithm{
			dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
		}},
		{domain: "other.example.test", suffix: "ed", algorithms: []dkim2model.Algorithm{
			dkim2model.AlgorithmEd25519SHA256,
		}},
	})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.lineageCreatedAt = now
	publisher := &fakeRotationPublisher{events: events, resolvedZones: map[string]string{
		"other.example.test.": "example.test.",
	}, results: []dnsupdate.PublishResult{
		dnsupdate.PublishCreated, dnsupdate.PublishAlreadyPresent, dnsupdate.PublishAlreadyPresent,
	}}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }
	var output bytes.Buffer
	manager.out = &output

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeReconciled || output.String() != "DKIM2 rotation outcome: reconciled\n" {
		t.Fatalf("automatic reconciliation result=%#v err=%v", result, err)
	}
	if publisher.resolveCalls != 2 || publisher.calls != 3 || proof.calls != 1 || repository.stageCalls != 0 ||
		repository.commitCalls != 0 || len(repository.deleteCalls) != 0 ||
		!slices.Contains(publisher.resolvedLogical, "example.test.") ||
		!slices.Contains(publisher.resolvedLogical, "other.example.test.") ||
		!slices.Equal(publisher.publishedZones, []string{"example.test.", "example.test.", "example.test."}) {
		t.Fatalf("resolve=%d logical=%v publish=%d zones=%v proof=%d stage=%d commit=%d delete=%v events=%v",
			publisher.resolveCalls, publisher.resolvedLogical, publisher.calls, publisher.publishedZones, proof.calls,
			repository.stageCalls, repository.commitCalls, repository.deleteCalls, *events)
	}
}

func TestDKIM2AutoResolvesEveryCurrentUpdateZoneBeforePublication(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "first", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "other.example.test", suffix: "second", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256}},
	})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.lineageCreatedAt = now
	publisher := &fakeRotationPublisher{events: events, resolveFailAt: 2, resolveFailErr: dnsupdate.ErrPublishUncertain}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }

	result, err := manager.Run()
	if err == nil || result == nil || publisher.resolveCalls != 2 || publisher.calls != 0 || proof.calls != 0 ||
		repository.stageCalls != 0 || repository.commitCalls != 0 || len(repository.deleteCalls) != 0 {
		t.Fatalf("result=%#v resolve=%d publish=%d proof=%d stage=%d commit=%d delete=%v err=%v events=%v",
			result, publisher.resolveCalls, publisher.calls, proof.calls, repository.stageCalls,
			repository.commitCalls, repository.deleteCalls, err, *events)
	}
}

func TestDKIM2AutoReportsIdleWhenEveryCurrentDNSRecordIsExact(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.lineageCreatedAt = now
	publisher := &fakeRotationPublisher{events: events, results: []dnsupdate.PublishResult{
		dnsupdate.PublishAlreadyPresent, dnsupdate.PublishAlreadyPresent,
	}}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }
	var output bytes.Buffer
	manager.out = &output

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeIdle || output.String() != "DKIM2 rotation outcome: idle\n" {
		t.Fatalf("exact current DNS result=%#v output=%q err=%v", result, output.String(), err)
	}
	if publisher.calls != 2 || proof.calls != 1 || repository.stageCalls != 0 || repository.commitCalls != 0 || len(repository.deleteCalls) != 0 {
		t.Fatalf("publish=%d proof=%d stage=%d commit=%d delete=%v events=%v",
			publisher.calls, proof.calls, repository.stageCalls, repository.commitCalls, repository.deleteCalls, *events)
	}
}

func TestDKIM2AutoReconciledReportingFailureDoesNotTriggerBlindRetry(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.lineageCreatedAt = now
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events, results: []dnsupdate.PublishResult{dnsupdate.PublishCreated}}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) {
		return &fakeRotationProof{events: events}, nil
	}
	manager.out = &failAfterMutationWriter{}

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeReconciled || !result.ReportingFailed ||
		repository.stageCalls != 0 || repository.commitCalls != 0 {
		t.Fatalf("result=%#v stage=%d commit=%d err=%v", result, repository.stageCalls, repository.commitCalls, err)
	}
}

func TestDKIM2AutoCurrentDNSFailureStopsBeforeLDAPMutation(t *testing.T) {
	for _, test := range []struct {
		name         string
		publisherErr error
		proofFailure bool
	}{
		{name: "publication conflict", publisherErr: dnsupdate.ErrPublishConflict},
		{name: "proof failure", proofFailure: true},
		{name: "cancelled publication", publisherErr: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256})
			manager, repository, events := newRotationHarness(t, current,
				&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
			defer repository.close()
			manager.cfg.DKIM2.RotationEnabled = true
			now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
			manager.now = func() time.Time { return now }
			repository.lineageCreatedAt = now
			publisher := &fakeRotationPublisher{events: events}
			if test.publisherErr != nil {
				publisher.failAt, publisher.failErr = 1, test.publisherErr
			}
			proof := &fakeRotationProof{events: events}
			if test.proofFailure {
				proof.failAt = 1
			}
			manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
			manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }

			result, err := manager.Run()
			if err == nil || result != nil && result.DKIM2Outcome != "" || repository.stageCalls != 0 ||
				repository.commitCalls != 0 || len(repository.deleteCalls) != 0 {
				t.Fatalf("result=%#v stage=%d commit=%d delete=%v events=%v err=%v",
					result, repository.stageCalls, repository.commitCalls, repository.deleteCalls, *events, err)
			}
		})
	}
}

func TestDKIM2AutoCurrentDNSInventoryIsBoundedBeforePublication(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "one", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "other.example", suffix: "two", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
	})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	manager.cfg.DKIM2.MaxCampaignBindings = 1
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.lineageCreatedAt = now
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("bounded inventory opened the DNS publisher")
		return nil, nil
	}

	result, err := manager.Run()
	if err == nil || result != nil && result.DKIM2Outcome != "" || repository.stageCalls != 0 ||
		repository.commitCalls != 0 || len(repository.deleteCalls) != 0 {
		t.Fatalf("result=%#v stage=%d commit=%d delete=%v events=%v err=%v",
			result, repository.stageCalls, repository.commitCalls, repository.deleteCalls, *events, err)
	}
}

func TestDKIM2AutoPreservesRetainedHistoryFailureClass(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	repository.fail["load-history"] = dkim2store.ErrMalformed

	_, err := manager.Run()
	if !errors.Is(err, dkim2store.ErrMalformed) {
		t.Fatalf("automatic history error = %v", err)
	}
}

func TestDKIM2AutoRotatesAllDueBindingsInOneGenerationAndNeverRetires(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "other.example", suffix: "other", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "example.test", suffix: "target", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
	})
	manager, repository, events := newRotationHarness(t, current, &cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	manager.now = func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }
	publisher := &fakeRotationPublisher{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	manager.newRotationRetirer = func(*config.Config) (dkim2RotationRetirer, error) {
		t.Fatal("automatic rotation constructed retirement dependency")
		return nil, nil
	}
	_, found := current.CredentialByDomainSelector("other.example", "selector-other-0")
	if !found {
		t.Fatal("other binding fixture missing")
	}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || publisher.calls != 2 || repository.stageCalls != 1 || repository.commitCalls != 1 {
		t.Fatalf("result=%#v publications=%d err=%v", result, publisher.calls, err)
	}
	if _, found := repository.pending.CredentialByDomainSelector("other.example", "selector-other-0"); found {
		t.Fatal("global campaign retained an old selector from a due binding")
	}
}

func TestDKIM2AutoRotatesTheDeterministicallySelectedFullBinding(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "selected", tenant: "a-tenant", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "example.test", suffix: "configured", tenant: "tenant-test", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
	})
	configuredBefore, found := current.CredentialByDomainSelector("example.test", "selector-configured-0")
	if !found {
		t.Fatal("configured same-domain binding missing")
	}
	manager, repository, events := newRotationHarness(t, current, &cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	manager.now = func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated {
		t.Fatalf("auto result=%#v err=%v", result, err)
	}
	_, found = repository.pending.CredentialByDomainSelector("example.test", "selector-configured-0")
	if found {
		t.Fatal("global campaign retained an old selector from a second due same-domain binding")
	}
	_ = configuredBefore
	if _, found := repository.pending.CredentialByDomainSelector("example.test", "selector-selected-0"); found {
		t.Fatal("deterministically selected binding retained its old selector")
	}
}

func TestDKIM2AutoFailsClosedOnDisabledOrIncompleteHistoryBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		enabled    bool
		incomplete bool
		future     bool
	}{
		{name: "default disabled"},
		{name: "incomplete lineage", enabled: true, incomplete: true},
		{name: "future lineage", enabled: true, future: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, repository, events := newRotationHarness(t,
				rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
				&cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
			defer repository.close()
			manager.cfg.DKIM2.RotationEnabled = test.enabled
			repository.historyIncomplete = test.incomplete
			manager.now = func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }
			if test.future {
				repository.lineageCreatedAt = manager.now().Add(time.Hour)
			}
			result, err := manager.Run()
			if err == nil || result != nil && result.DKIM2Outcome == DKIM2OutcomeActivated || repository.stageCalls != 0 {
				t.Fatalf("result=%#v events=%v stage=%d err=%v", result, *events, repository.stageCalls, err)
			}
		})
	}
}

func TestExactPendingSuccessorRejectsNoncontiguousRetainedRoots(t *testing.T) {
	history := dkim2store.NewRetainedHistory([]dkim2store.GenerationRoot{
		{Number: 1, State: dkim2model.DatasetStateCommitted},
		{Number: 3, State: dkim2model.DatasetStateCommitted},
	}, true, nil, nil)
	if _, err := exactPendingSuccessor(history, 3); !errors.Is(err, dkim2store.ErrMalformed) {
		t.Fatalf("noncontiguous roots accepted: %v", err)
	}
}

func TestLifecycleMutationFenceIsExclusiveAndCancellationAware(t *testing.T) {
	fence := newLifecycleMutationFence()
	release, err := fence.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if secondRelease, acquireErr := fence.acquire(ctx); !errors.Is(acquireErr, context.Canceled) || secondRelease != nil {
		t.Fatalf("cancelled concurrent acquisition succeeded: release=%v err=%v", secondRelease != nil, acquireErr)
	}
	release()
	secondRelease, err := fence.acquire(context.Background())
	if err != nil || secondRelease == nil {
		t.Fatalf("released fence was not reusable: %v", err)
	}
	secondRelease()
}

func TestDKIM2ObservationClassifiesCandidateDualChannelStates(t *testing.T) {
	for _, test := range []struct {
		name          string
		state         dkim2model.DatasetState
		observations  []dnsupdate.PresenceObservation
		expectedPhase DKIM2Outcome
	}{
		{name: "staged", state: dkim2model.DatasetStateStaging,
			observations: []dnsupdate.PresenceObservation{{Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceExact}}, expectedPhase: "staged"},
		{name: "dns pending", state: dkim2model.DatasetStateStaging,
			observations: []dnsupdate.PresenceObservation{{Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceAbsent}}, expectedPhase: "dns-pending"},
		{name: "dns conflict", state: dkim2model.DatasetStateStaging,
			observations: []dnsupdate.PresenceObservation{{Authoritative: dnsupdate.PresenceConflict, Recursive: dnsupdate.PresenceExact}}, expectedPhase: "dns-conflict"},
		{name: "committed unreachable", state: dkim2model.DatasetStateCommitted,
			observations: []dnsupdate.PresenceObservation{{Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceExact}}, expectedPhase: "committed-unreachable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current, candidate := rotationSuccessorPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
			if test.state == dkim2model.DatasetStateCommitted {
				committed, err := cloneGenerationWithState(candidate, test.state)
				_ = candidate.Close()
				if err != nil {
					t.Fatal(err)
				}
				candidate = committed
			}
			manager, repository, _ := newRotationHarness(t, current, &cli.Options{Observe: true, Domains: []string{"example.test"}})
			defer repository.close()
			repository.pending, repository.observed = candidate, current.Number()
			observer := &fakeDualObserver{observations: test.observations}
			manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) { return observer, nil }
			var output bytes.Buffer
			manager.out = &output
			result, err := manager.Run()
			if err != nil || result.DKIM2Outcome != test.expectedPhase {
				t.Fatalf("result=%#v output=%q err=%v", result, output.String(), err)
			}
			if output.Len() > 240 || bytes.Contains(output.Bytes(), []byte("handle-")) || bytes.Contains(output.Bytes(), []byte("p=")) {
				t.Fatalf("unsafe observation output: %q", output.String())
			}
		})
	}
}

func TestDKIM2ObservationRejectsSameDomainCandidateForDifferentBinding(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "configured", tenant: "tenant-test", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "example.test", suffix: "foreign", tenant: "other-tenant", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
	})
	manager, repository, _ := newRotationHarness(t, current,
		&cli.Options{Observe: true, Domains: []string{"example.test"}, Size: 2048})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "other-tenant", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	repository.pending, repository.observed = candidate, 1
	manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) {
		return &fakeDualObserver{observations: []dnsupdate.PresenceObservation{{
			Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceExact,
		}}}, nil
	}
	result, err := manager.Run()
	if err == nil || result != nil && result.DKIM2Outcome != "" {
		t.Fatalf("foreign same-domain observation result=%#v err=%v", result, err)
	}
}

func TestDKIM2ObservationClassifiesPostActivationOverlapCacheAndRetirement(t *testing.T) {
	exact := dnsupdate.PresenceObservation{Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceExact}
	for _, test := range []struct {
		name          string
		activationAge time.Duration
		old           dnsupdate.PresenceObservation
		expectedPhase DKIM2Outcome
	}{
		{name: "observing overlap", activationAge: time.Hour, old: exact, expectedPhase: "observing"},
		{name: "retire eligible", activationAge: 8 * 24 * time.Hour, old: exact, expectedPhase: "retire-eligible"},
		{name: "recursive cache", activationAge: 8 * 24 * time.Hour,
			old: dnsupdate.PresenceObservation{Authoritative: dnsupdate.PresenceAbsent, Recursive: dnsupdate.PresenceExact}, expectedPhase: "observing"},
		{name: "retired", activationAge: 8 * 24 * time.Hour,
			old: dnsupdate.PresenceObservation{Authoritative: dnsupdate.PresenceAbsent, Recursive: dnsupdate.PresenceAbsent}, expectedPhase: "retired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			predecessor, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
			manager, repository, _ := newRotationHarness(t, current, &cli.Options{Observe: true, Domains: []string{"example.test"}})
			defer repository.close()
			repository.retained[predecessor.Number()] = predecessor
			now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
			manager.now = func() time.Time { return now }
			repository.activation = dkim2store.CurrentActivation{Generation: current.Number(), ModifiedAt: now.Add(-test.activationAge)}
			observer := &fakeDualObserver{observations: []dnsupdate.PresenceObservation{exact, test.old}}
			manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) { return observer, nil }
			result, err := manager.Run()
			if err != nil || result.DKIM2Outcome != test.expectedPhase {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestDKIM2ObservationTreatsCardinalityNeutralPartialRetirementAsObserving(t *testing.T) {
	predecessor, current := rotationCommittedPair(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	})
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{Observe: true, Domains: []string{"example.test"}})
	defer repository.close()
	repository.retained[predecessor.Number()] = predecessor
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.activation = dkim2store.CurrentActivation{Generation: current.Number(), ModifiedAt: now.Add(-8 * 24 * time.Hour)}
	exact := dnsupdate.PresenceObservation{Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceExact}
	observer := &fakeDualObserver{observations: []dnsupdate.PresenceObservation{
		exact, exact,
		exact,
		{Authoritative: dnsupdate.PresenceAbsent, Recursive: dnsupdate.PresenceExact},
	}}
	manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) { return observer, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != "observing" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestDKIM2ObservationRejectsUncertainCandidateChannel(t *testing.T) {
	current, candidate := rotationSuccessorPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{Observe: true, Domains: []string{"example.test"}})
	defer repository.close()
	repository.pending, repository.observed = candidate, current.Number()
	observer := &fakeDualObserver{observations: []dnsupdate.PresenceObservation{{
		Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceUncertain,
	}}}
	manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) { return observer, nil }
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == "dns-pending" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestDKIM2ObservationIdleUsesNoDNSWriteOrTSIGSurface(t *testing.T) {
	manager, repository, _ := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Observe: true, Domains: []string{"example.test"}})
	defer repository.close()
	observer := &fakeDualObserver{}
	manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) { return observer, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeIdle || observer.calls != 0 {
		t.Fatalf("result=%#v DNS calls=%d err=%v", result, observer.calls, err)
	}
}

func TestDKIM2ForwardRollbackRebasesAndActivatesStrictlyForward(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current, &cli.Options{
		RollbackFromGenerationSet: true, RollbackFromGeneration: source.Number(),
		Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	publisher := &fakeRotationPublisher{events: events, results: []dnsupdate.PublishResult{dnsupdate.PublishAlreadyPresent}}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }

	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated {
		t.Fatalf("forward rollback result=%#v err=%v", result, err)
	}
	if repository.observed != 3 || repository.pending == nil || repository.pending.Number() != 3 || repository.stageCalls != 1 {
		t.Fatalf("observed=%d pending=%v stage=%d", repository.observed, repository.pending, repository.stageCalls)
	}
	if repository.current.Number() != 2 {
		t.Fatalf("fake predecessor pointer was moved backward to %d", repository.current.Number())
	}
}

func TestDKIM2ForwardRollbackDryRunPerformsNoStageOrDNSConstruction(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256})
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{
		RollbackFromGenerationSet: true, RollbackFromGeneration: source.Number(),
		Domains: []string{"example.test"}, UpdateDNS: true, DryRun: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed during rollback dry-run")
		return nil, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) {
		t.Fatal("proof constructed during rollback dry-run")
		return nil, nil
	}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun || repository.stageCalls != 0 {
		t.Fatalf("dry-run result=%#v stage=%d err=%v", result, repository.stageCalls, err)
	}
}

func TestDKIM2NormalResumeRejectsStoredForwardRollbackIntent(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	transition, err := dkim2model.PlanForwardRollback(dkim2model.ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: current.Number() + 1,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := transition.Generation()
	_ = transition.Close()
	if err != nil {
		t.Fatal(err)
	}
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{
		Rotate: true, ResumeGenerationSet: true, ResumeGeneration: candidate.Number(),
		Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	repository.pending, repository.observed = candidate, current.Number()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed for rollback intent under normal resume")
		return nil, nil
	}
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeActivated || repository.commitCalls != 0 {
		t.Fatalf("result=%#v commits=%d err=%v", result, repository.commitCalls, err)
	}
}

func TestDKIM2AutoRejectsStoredForwardRollbackIntentBeforeDNSOrCommit(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	transition, err := dkim2model.PlanForwardRollback(dkim2model.ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: current.Number() + 1,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := transition.Generation()
	_ = transition.Close()
	if err != nil {
		t.Fatal(err)
	}
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.cfg.DKIM2.RotationEnabled = true
	repository.retained[source.Number()] = source
	repository.pending, repository.observed = candidate, current.Number()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed for rollback intent under automation")
		return nil, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) {
		t.Fatal("proof constructed for rollback intent under automation")
		return nil, nil
	}
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeActivated || repository.commitCalls != 0 {
		t.Fatalf("result=%#v commits=%d err=%v", result, repository.commitCalls, err)
	}
}

func TestDKIM2RollbackResumeRejectsStoredFreshRotationIntent(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256})
	history := publicHistoryForGeneration(current)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{
		Current: current, NextGeneration: current.Number() + 1, TenantID: "tenant-test", Domain: "example.test",
		Use: dkim2model.ProfileUseOriginator, RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{
		RollbackFromGenerationSet: true, RollbackFromGeneration: source.Number(),
		ResumeGenerationSet: true, ResumeGeneration: candidate.Number(),
		Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	repository.pending, repository.observed = candidate, current.Number()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed for fresh rotation under rollback resume")
		return nil, nil
	}
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeActivated || repository.commitCalls != 0 {
		t.Fatalf("result=%#v commits=%d err=%v", result, repository.commitCalls, err)
	}
}

func TestDKIM2ForwardRollbackResumeReconcilesPartialDNSAndLostActivation(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	})
	transition, err := dkim2model.PlanForwardRollback(dkim2model.ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: current.Number() + 1,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := transition.Generation()
	_ = transition.Close()
	if err != nil {
		t.Fatal(err)
	}
	manager, repository, events := newRotationHarness(t, current, &cli.Options{
		RollbackFromGenerationSet: true, RollbackFromGeneration: source.Number(), ResumeGenerationSet: true,
		ResumeGeneration: candidate.Number(), Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	repository.pending, repository.observed = candidate, current.Number()
	repository.activationLost = true
	publisher := &fakeRotationPublisher{events: events, results: []dnsupdate.PublishResult{
		dnsupdate.PublishAlreadyPresent, dnsupdate.PublishCreated,
	}}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || publisher.calls != 2 || repository.observed != 3 {
		t.Fatalf("result=%#v publications=%d observed=%d err=%v", result, publisher.calls, repository.observed, err)
	}
}

func TestDKIM2ForwardRollbackReconcilesLostStageResponse(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current, &cli.Options{
		RollbackFromGenerationSet: true, RollbackFromGeneration: source.Number(),
		Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	repository.stageLost = true
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || repository.stageCalls != 1 {
		t.Fatalf("result=%#v stage=%d err=%v", result, repository.stageCalls, err)
	}
}

func TestDKIM2ForwardRollbackAlreadyCurrentResumeIsIdempotent(t *testing.T) {
	source, current := rotationCommittedPair(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	transition, err := dkim2model.PlanForwardRollback(dkim2model.ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: current.Number() + 1,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := transition.Generation()
	_ = transition.Close()
	if err != nil {
		t.Fatal(err)
	}
	committed, err := cloneGenerationWithState(candidate, dkim2model.DatasetStateCommitted)
	_ = candidate.Close()
	if err != nil {
		t.Fatal(err)
	}
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{
		RollbackFromGenerationSet: true, RollbackFromGeneration: source.Number(), ResumeGenerationSet: true,
		ResumeGeneration: committed.Number(), Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048,
	})
	defer repository.close()
	repository.retained[source.Number()] = source
	repository.pending, repository.observed = committed, committed.Number()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed for already-current rollback")
		return nil, nil
	}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeAlreadyActivated || repository.commitCalls != 0 {
		t.Fatalf("result=%#v commits=%d err=%v", result, repository.commitCalls, err)
	}
}

func TestDKIM2RetirementRequiresOverlapAndRechecksCurrentBeforeEveryExactDelete(t *testing.T) {
	manager, repository, events, retirer := newRetirementHarness(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	}, []dnsupdate.PresenceState{dnsupdate.PresenceExact, dnsupdate.PresenceExact})
	defer repository.close()
	repository.activation.ModifiedAt = manager.now().Add(-time.Duration(manager.cfg.DKIM2.RetirementMinOverlapSeconds) * time.Second)
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeRetired {
		t.Fatalf("retirement result=%#v err=%v events=%v", result, err, *events)
	}
	if retirer.deleteCall != 2 || repository.activationCalls != 3 {
		t.Fatalf("deletes=%d activation-reads=%d", retirer.deleteCall, repository.activationCalls)
	}
}

func TestDKIM2RetirementFailsClosedWhenSuccessorExists(t *testing.T) {
	manager, repository, _, retirer := newRetirementHarness(t,
		[]dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256},
		[]dnsupdate.PresenceState{dnsupdate.PresenceExact},
	)
	defer repository.close()
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{
		Current: repository.current, NextGeneration: repository.current.Number() + 1,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.pending = candidate
	result, err := manager.Run()
	if err == nil || result != nil && result.DKIM2Outcome == DKIM2OutcomeRetired || retirer.deleteCall != 0 {
		t.Fatalf("successor retirement result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
	}
}

func TestDKIM2RetirementRejectsInsufficientOverlapBeforeDelete(t *testing.T) {
	manager, repository, _, retirer := newRetirementHarness(t,
		[]dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256},
		[]dnsupdate.PresenceState{dnsupdate.PresenceExact},
	)
	defer repository.close()
	repository.activation.ModifiedAt = manager.now().Add(-time.Hour)
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeRetired || retirer.deleteCall != 0 {
		t.Fatalf("result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
	}
}

func TestDKIM2RetirementPartialStateRequiresExplicitResumeAndNeverRecreatesAbsentRecords(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "resume"}[resume], func(t *testing.T) {
			manager, repository, _, retirer := newRetirementHarness(t,
				[]dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256},
				[]dnsupdate.PresenceState{dnsupdate.PresenceAbsent, dnsupdate.PresenceExact},
			)
			defer repository.close()
			manager.opts.ResumeRetirement = resume
			result, err := manager.Run()
			if !resume {
				if err == nil || retirer.deleteCall != 0 {
					t.Fatalf("initial result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
				}
				return
			}
			if err != nil || result.DKIM2Outcome != DKIM2OutcomeRetired || retirer.deleteCall != 1 {
				t.Fatalf("resume result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
			}
		})
	}
}

func TestDKIM2RetirementStopsWhenCurrentChangesBeforeDelete(t *testing.T) {
	manager, repository, _, retirer := newRetirementHarness(t,
		[]dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256},
		[]dnsupdate.PresenceState{dnsupdate.PresenceExact},
	)
	defer repository.close()
	repository.changeCurrentAt = 2
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeRetired || retirer.deleteCall != 0 {
		t.Fatalf("result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
	}
}

func TestDKIM2RetirementDryRunNeverCallsExactDelete(t *testing.T) {
	manager, repository, _, retirer := newRetirementHarness(t,
		[]dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256},
		[]dnsupdate.PresenceState{dnsupdate.PresenceExact},
	)
	defer repository.close()
	manager.opts.DryRun = true
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun || retirer.deleteCall != 0 {
		t.Fatalf("result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
	}
}

func TestDKIM2LifecycleDeadlineIncludesInteractiveAuthorization(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Interactive: true, Size: 2048})
	defer repository.close()
	var cancel context.CancelFunc
	manager.newLifecycleContext = func(time.Duration) (context.Context, context.CancelFunc) {
		ctx, contextCancel := context.WithCancel(context.Background())
		cancel = contextCancel
		return ctx, contextCancel
	}
	manager.in = cancelYesReader{cancel: func() { cancel() }}
	result, err := manager.Run()
	if err == nil || result != nil || len(*events) != 0 || repository.stageCalls != 0 {
		t.Fatalf("result=%#v events=%v stage=%d err=%v", result, *events, repository.stageCalls, err)
	}
}

func TestDKIM2RetirementPromptDoesNotClaimLDAPPublication(t *testing.T) {
	manager, repository, _, _ := newRetirementHarness(t,
		[]dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256},
		[]dnsupdate.PresenceState{dnsupdate.PresenceExact},
	)
	defer repository.close()
	manager.opts.Yes = false
	manager.opts.Interactive = true
	manager.in = bytes.NewBufferString("no\n")
	var output bytes.Buffer
	manager.out = &output
	if result, err := manager.Run(); err == nil || result != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if bytes.Contains(bytes.ToLower(output.Bytes()), []byte("ldap")) || bytes.Contains(bytes.ToLower(output.Bytes()), []byte("generation")) {
		t.Fatalf("misleading retirement prompt: %q", output.String())
	}
}

func TestDKIM2CompletedRetirementReportingFailureIsSchedulerSafe(t *testing.T) {
	manager, repository, _, retirer := newRetirementHarness(t,
		[]dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256},
		[]dnsupdate.PresenceState{dnsupdate.PresenceExact},
	)
	defer repository.close()
	manager.out = &failAfterMutationWriter{}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeRetired || !result.ReportingFailed || retirer.deleteCall != 1 {
		t.Fatalf("result=%#v deletes=%d err=%v", result, retirer.deleteCall, err)
	}
}

func newRetirementHarness(t *testing.T, algorithms []dkim2model.Algorithm, states []dnsupdate.PresenceState) (*DKIM2Manager, *fakeRotationRepository, *[]string, *fakeLifecycleRetirer) {
	t.Helper()
	predecessor, current := rotationCommittedPair(t, algorithms)
	opts := &cli.Options{
		RetireGenerationSet: true, RetireGeneration: predecessor.Number(), Domains: []string{"example.test"},
		UpdateDNS: true, Yes: true, AttestRuntimeReload: true, AttestReadiness: true, AttestQueues: true,
		AttestEmittedSignatures: true, AttestExternalVerification: true, AttestBackup: true, AttestRollbackAuthority: true,
	}
	manager, repository, events := newRotationHarness(t, current, opts)
	repository.retained[predecessor.Number()] = predecessor
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.activation = dkim2store.CurrentActivation{Generation: current.Number(), ModifiedAt: now.Add(-8 * 24 * time.Hour)}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	retirer := &fakeLifecycleRetirer{states: states}
	manager.newRotationRetirer = func(*config.Config) (dkim2RotationRetirer, error) { return retirer, nil }
	return manager, repository, events, retirer
}

func rotationSuccessorPair(t *testing.T, algorithms []dkim2model.Algorithm) (*dkim2model.Generation, *dkim2model.Generation) {
	t.Helper()
	current := rotationGeneration(t, algorithms)
	history := publicHistoryForGeneration(current)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{
		Current: current, NextGeneration: current.Number() + 1, TenantID: "tenant-test", Domain: "example.test",
		Use: dkim2model.ProfileUseOriginator, RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history,
	})
	if err != nil {
		_ = current.Close()
		t.Fatal(err)
	}
	return current, candidate
}

func rotationCommittedPair(t *testing.T, algorithms []dkim2model.Algorithm) (*dkim2model.Generation, *dkim2model.Generation) {
	t.Helper()
	predecessor, candidate := rotationSuccessorPair(t, algorithms)
	committed, err := cloneGenerationWithState(candidate, dkim2model.DatasetStateCommitted)
	_ = candidate.Close()
	if err != nil {
		_ = predecessor.Close()
		t.Fatal(err)
	}
	return predecessor, committed
}

func publicHistoryForGeneration(generation *dkim2model.Generation) dkim2store.RetainedHistory {
	selectors := make([]string, 0, len(generation.Credentials()))
	for _, credential := range generation.Credentials() {
		selectors = append(selectors, credential.Selector())
	}
	handles := make([]string, 0, len(generation.Handles()))
	for _, handle := range generation.Handles() {
		handles = append(handles, handle.ID())
	}
	return dkim2store.NewRetainedHistory(
		[]dkim2store.GenerationRoot{{Number: generation.Number(), State: generation.State()}}, true, selectors, handles,
	)
}
