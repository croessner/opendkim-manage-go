package app

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

// recordingRotationPublisher records every published record for content checks.
type recordingRotationPublisher struct {
	inner   *fakeRotationPublisher
	records []dnsupdate.ExpectedTXT
}

// ResolveUpdateZone delegates to the fake publisher.
func (p *recordingRotationPublisher) ResolveUpdateZone(ctx context.Context, zone string) (string, error) {
	return p.inner.ResolveUpdateZone(ctx, zone)
}

// PublishIfAbsent records the exact record and delegates to the fake publisher.
func (p *recordingRotationPublisher) PublishIfAbsent(ctx context.Context, zone string, record dnsupdate.ExpectedTXT) (dnsupdate.PublishResult, error) {
	p.records = append(p.records, record)
	return p.inner.PublishIfAbsent(ctx, zone, record)
}

// TestDKIM2RotationExtendsDualBindingWithComposite proves --keytype all on a
// dual binding stages, publishes, proves, and activates fresh RSA, Ed25519,
// and mldsa44-ed25519-sha512 keys, with the composite record carrying no h=.
func TestDKIM2RotationExtendsDualBindingWithComposite(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	}), &cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "all"})
	defer repository.close()
	publisher := &recordingRotationPublisher{inner: &fakeRotationPublisher{events: events}}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || len(publisher.records) != 3 {
		t.Fatalf("result=%#v records=%d err=%v", result, len(publisher.records), err)
	}
	composite := 0
	for _, record := range publisher.records {
		if strings.HasPrefix(record.Content, "v=DKIM1; k=mldsa44-ed25519-sha512; p=") {
			composite++
			if strings.Contains(record.Content, "h=") || !strings.HasSuffix(record.Owner, "._domainkey.example.test.") {
				t.Fatalf("composite record = %q owner %q", record.Content, record.Owner)
			}
		}
	}
	if composite != 1 {
		t.Fatalf("composite records = %d", composite)
	}
}

// TestDKIM2RotationRefusesToDropAnAlgorithm proves a narrower --keytype fails
// closed before any DNS publication.
func TestDKIM2RotationRefusesToDropAnAlgorithm(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	}), &cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048, KeyType: "composite"})
	defer repository.close()
	publisher := &fakeRotationPublisher{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	if _, err := manager.Run(); err == nil || publisher.calls != 0 {
		t.Fatalf("narrowing rotation err=%v publications=%d", err, publisher.calls)
	}
}

// TestLegacyManagerRejectsDKIM2OnlyKeyTypes proves legacy OpenDKIM mode
// refuses the composite key types before opening any LDAP connection.
func TestLegacyManagerRejectsDKIM2OnlyKeyTypes(t *testing.T) {
	for _, keyType := range []string{"composite", "all"} {
		manager, err := NewManager(&config.Config{}, &cli.Options{KeyType: keyType})
		if err == nil || manager != nil || !strings.Contains(err.Error(), "requires --mode dkim2") {
			t.Fatalf("NewManager(--keytype %s) = %v, %v", keyType, manager, err)
		}
	}
}

// rotationExtendedCommittedPair rotates a dual binding to all three algorithms.
func rotationExtendedCommittedPair(t *testing.T) (*dkim2model.Generation, *dkim2model.Generation) {
	t.Helper()
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256})
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{
		Current: current, NextGeneration: current.Number() + 1, TenantID: "tenant-test", Domain: "example.test",
		Use: dkim2model.ProfileUseOriginator, Algorithms: dkim2model.SigningAlgorithms(), RSABits: 2048,
		AllocationAttempts: 16, Random: rand.Reader, History: publicHistoryForGeneration(current),
	})
	if err != nil {
		_ = current.Close()
		t.Fatal(err)
	}
	committed, err := cloneGenerationWithState(candidate, dkim2model.DatasetStateCommitted)
	_ = candidate.Close()
	if err != nil {
		_ = current.Close()
		t.Fatal(err)
	}
	return current, committed
}

// TestDKIM2ObservationClassifiesExtendedRotationForRetirement proves an
// activated extension proves three active records and retires the two old ones.
func TestDKIM2ObservationClassifiesExtendedRotationForRetirement(t *testing.T) {
	predecessor, current := rotationExtendedCommittedPair(t)
	manager, repository, _ := newRotationHarness(t, current, &cli.Options{Observe: true, Domains: []string{"example.test"}})
	defer repository.close()
	repository.retained[predecessor.Number()] = predecessor
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	repository.activation = dkim2store.CurrentActivation{Generation: current.Number(), ModifiedAt: now.Add(-8 * 24 * time.Hour)}
	exact := dnsupdate.PresenceObservation{Authoritative: dnsupdate.PresenceExact, Recursive: dnsupdate.PresenceExact}
	observer := &fakeDualObserver{observations: []dnsupdate.PresenceObservation{exact, exact, exact, exact, exact}}
	manager.newPresenceObserver = func(*config.Config) (dkim2PresenceObserver, error) { return observer, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != "retire-eligible" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
