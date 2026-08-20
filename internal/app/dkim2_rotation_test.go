package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type fakeRotationRepository struct {
	current           *dkim2model.Generation
	pending           *dkim2model.Generation
	foreignPending    *dkim2model.Generation
	retained          map[uint64]*dkim2model.Generation
	activation        dkim2store.CurrentActivation
	activationCalls   int
	changeCurrentAt   int
	historyIncomplete bool
	lineageCreatedAt  time.Time
	observed          uint64
	events            *[]string
	fail              map[string]error
	stageLost         bool
	activationLost    bool
	commitOnlyLost    bool
	failAfterCommit   bool
	stageCalls        int
	commitCalls       int
	campaignMetadata  *dkim2model.CandidateMetadata
	deleteCalls       []uint64
	deleteFailures    int
	inventoryOverride *dkim2store.GenerationInventory
}

func (f *fakeRotationRepository) event(name string) error {
	*f.events = append(*f.events, name)
	return f.fail[name]
}

func (f *fakeRotationRepository) LoadCurrent(context.Context) (*dkim2model.Generation, error) {
	if err := f.event("load-current"); err != nil {
		return nil, err
	}
	if f.current == nil {
		return nil, nil
	}
	return f.current.Clone()
}

func (f *fakeRotationRepository) LoadRetainedHistory(context.Context, int) (dkim2store.RetainedHistory, error) {
	if err := f.event("load-history"); err != nil {
		return dkim2store.RetainedHistory{}, err
	}
	var roots []dkim2store.GenerationRoot
	var selectors, handles []string
	var generations []*dkim2model.Generation
	for _, generation := range []*dkim2model.Generation{f.current, f.pending} {
		if generation == nil {
			continue
		}
		generations = append(generations, generation)
		roots = append(roots, dkim2store.GenerationRoot{Number: generation.Number(), State: generation.State()})
		for _, credential := range generation.Credentials() {
			selectors = append(selectors, credential.Selector())
		}
		for _, handle := range generation.Handles() {
			handles = append(handles, handle.ID())
		}
	}
	for number, generation := range f.retained {
		if generation == nil || number == f.current.Number() || f.pending != nil && number == f.pending.Number() {
			continue
		}
		generations = append(generations, generation)
		roots = append(roots, dkim2store.GenerationRoot{Number: generation.Number(), State: generation.State()})
		for _, credential := range generation.Credentials() {
			selectors = append(selectors, credential.Selector())
		}
		for _, handle := range generation.Handles() {
			handles = append(handles, handle.ID())
		}
	}
	lineage := dkim2model.LineageHistory{Complete: true}
	for _, generation := range generations {
		for _, credential := range generation.Credentials() {
			profile, found := generation.ProfileByID(credential.ProfileID())
			if !found {
				return dkim2store.RetainedHistory{}, dkim2store.ErrMalformed
			}
			var policy dkim2model.Policy
			count := 0
			for _, candidate := range generation.Policies() {
				if candidate.ProfileID() == profile.ID() {
					policy = candidate
					count++
				}
			}
			createdAt := f.lineageCreatedAt
			if createdAt.IsZero() {
				createdAt = time.Date(2020, 1, int(generation.Number()), 0, 0, 0, 0, time.UTC)
			}
			fact, err := dkim2model.NewLineageFact(generation.Number(), createdAt.Format("20060102150405Z"),
				policy.TenantID(), profile.SigningDomain(), policy.Use(), credential.Selector(), credential.Algorithm(),
				credential.PublicSPKIDER(), credential.HandleID())
			if err != nil || count != 1 {
				return dkim2store.RetainedHistory{}, dkim2store.ErrMalformed
			}
			lineage.Facts = append(lineage.Facts, fact)
		}
	}
	if f.historyIncomplete {
		return dkim2store.NewRetainedHistory(roots, false, selectors, handles), nil
	}
	return dkim2store.NewRetainedHistoryWithLineage(roots, selectors, handles, lineage)
}

func (f *fakeRotationRepository) Publish(context.Context, uint64, *dkim2model.Generation) error {
	return errors.New("legacy publish must not be used for rotation")
}

func (f *fakeRotationRepository) LoadRetainedGeneration(_ context.Context, number uint64, _ int) (*dkim2model.Generation, error) {
	if err := f.event("load-retained"); err != nil {
		return nil, err
	}
	if f.current != nil && f.current.Number() == number {
		return f.current.Clone()
	}
	if f.pending != nil && f.pending.Number() == number {
		return f.pending.Clone()
	}
	generation := f.retained[number]
	if generation == nil {
		return nil, dkim2store.ErrMalformed
	}
	return generation.Clone()
}

func (f *fakeRotationRepository) LoadGenerationCreatedAt(context.Context, uint64) (time.Time, error) {
	return time.Time{}, errors.New("generation time is outside manual rotation")
}

func (f *fakeRotationRepository) LoadCurrentActivation(context.Context) (dkim2store.CurrentActivation, error) {
	if err := f.event("load-activation"); err != nil {
		return dkim2store.CurrentActivation{}, err
	}
	f.activationCalls++
	activation := f.activation
	if f.changeCurrentAt > 0 && f.activationCalls >= f.changeCurrentAt {
		activation.Generation++
	}
	return activation, nil
}

func (f *fakeRotationRepository) Stage(_ context.Context, candidate *dkim2model.Generation, _ int) (*dkim2store.PreparedGeneration, error) {
	f.stageCalls++
	if err := f.event("stage"); err != nil && !f.stageLost {
		if f.foreignPending != nil {
			if f.pending != nil {
				_ = f.pending.Close()
			}
			f.pending, _ = f.foreignPending.Clone()
			f.observed = candidate.Number() - 1
		}
		return nil, err
	}
	if f.pending != nil {
		_ = f.pending.Close()
	}
	owned, err := candidate.Clone()
	if err != nil {
		return nil, err
	}
	f.pending = owned
	f.observed = candidate.Number() - 1
	if f.stageLost {
		return nil, dkim2store.ErrUnavailable
	}
	return dkim2store.NewPreparedGeneration(candidate.Number()-1, f.observed, candidate)
}

func (f *fakeRotationRepository) LoadPending(_ context.Context, number uint64, _ int) (*dkim2store.PreparedGeneration, error) {
	if err := f.event("load-pending"); err != nil {
		return nil, err
	}
	if f.failAfterCommit && f.commitCalls > 0 {
		return nil, errors.New("synthetic final readback failure")
	}
	if f.pending == nil || f.pending.Number() != number {
		return nil, dkim2store.ErrMalformed
	}
	if f.campaignMetadata == nil {
		return dkim2store.NewPreparedGeneration(number-1, f.observed, f.pending)
	}
	return dkim2store.NewCampaignPreparedGeneration(number-1, f.observed, f.pending, *f.campaignMetadata)
}

func (f *fakeRotationRepository) StageCampaign(_ context.Context, candidate *dkim2model.Generation, metadata dkim2model.CandidateMetadata) (*dkim2store.PreparedGeneration, error) {
	f.stageCalls++
	if err := f.event("stage"); err != nil && !f.stageLost {
		return nil, err
	}
	if f.pending != nil {
		_ = f.pending.Close()
	}
	owned, err := candidate.Clone()
	if err != nil {
		return nil, err
	}
	f.pending, f.observed, f.campaignMetadata = owned, candidate.Number()-1, &metadata
	if f.stageLost {
		return nil, dkim2store.ErrUnavailable
	}
	return dkim2store.NewCampaignPreparedGeneration(candidate.Number()-1, f.observed, candidate, metadata)
}

func (f *fakeRotationRepository) CommitAndSwitch(_ context.Context, number uint64, _ int) error {
	f.commitCalls++
	if err := f.event("commit-switch"); err != nil && !f.activationLost {
		return err
	}
	if f.pending == nil || f.pending.Number() != number {
		return dkim2store.ErrMalformed
	}
	committed, err := generationWithState(f.pending, dkim2model.DatasetStateCommitted)
	if err != nil {
		return err
	}
	_ = f.pending.Close()
	f.pending = committed
	if f.commitOnlyLost {
		return dkim2store.ErrUnavailable
	}
	f.observed = number
	if f.activationLost {
		return dkim2store.ErrUnavailable
	}
	return nil
}

func (f *fakeRotationRepository) CommitCampaignAndSwitch(_ context.Context, prepared *dkim2store.PreparedGeneration) error {
	if prepared == nil {
		return dkim2store.ErrMalformed
	}
	return f.CommitAndSwitch(context.Background(), prepared.CandidateNumber(), 0)
}

func (f *fakeRotationRepository) InventoryGenerations(context.Context) (dkim2store.GenerationInventory, error) {
	if f.inventoryOverride != nil {
		return dkim2store.GenerationInventory{Current: f.inventoryOverride.Current,
			Roots: append([]dkim2store.GenerationInventoryRoot(nil), f.inventoryOverride.Roots...)}, nil
	}
	current := f.observed
	if current == 0 && f.current != nil {
		current = f.current.Number()
	}
	roots := make([]dkim2store.GenerationInventoryRoot, 0, len(f.retained)+2)
	seen := map[uint64]struct{}{}
	for _, generation := range f.retained {
		if generation != nil {
			roots = append(roots, dkim2store.GenerationInventoryRoot{Number: generation.Number(), Schema: dkim2model.SchemaVersionV3,
				State: generation.State(), WasActive: true, Complete: true})
			seen[generation.Number()] = struct{}{}
		}
	}
	for _, generation := range []*dkim2model.Generation{f.current, f.pending} {
		if generation == nil {
			continue
		}
		if _, found := seen[generation.Number()]; found {
			continue
		}
		roots = append(roots, dkim2store.GenerationInventoryRoot{Number: generation.Number(), Schema: dkim2model.SchemaVersionV3,
			State: generation.State(), WasActive: true, Complete: true})
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Number < roots[j].Number })
	return dkim2store.GenerationInventory{Current: current, Roots: roots}, nil
}

func (f *fakeRotationRepository) DeleteGeneration(_ context.Context, plan dkim2store.GenerationPurgePlan) error {
	generation := plan.Generation()
	f.deleteCalls = append(f.deleteCalls, generation)
	if f.deleteFailures > 0 {
		f.deleteFailures--
		return dkim2store.ErrOutcomeUncertain
	}
	if f.inventoryOverride != nil {
		for index, root := range f.inventoryOverride.Roots {
			if root.Number == generation {
				f.inventoryOverride.Roots = append(f.inventoryOverride.Roots[:index], f.inventoryOverride.Roots[index+1:]...)
				break
			}
		}
	}
	delete(f.retained, generation)
	return nil
}

func generationWithState(source *dkim2model.Generation, state dkim2model.DatasetState) (*dkim2model.Generation, error) {
	materials := source.KeyMaterials()
	defer closeMaterials(materials)
	return dkim2model.NewGenerationWithState(source.Number(), state, source.Handles(), source.Profiles(), source.Credentials(), source.Policies(), materials)
}

func (f *fakeRotationRepository) close() {
	if f.current != nil {
		_ = f.current.Close()
	}
	if f.pending != nil {
		_ = f.pending.Close()
	}
	if f.foreignPending != nil {
		_ = f.foreignPending.Close()
	}
	for _, generation := range f.retained {
		_ = generation.Close()
	}
}

type fakeRotationPublisher struct {
	events          *[]string
	results         []dnsupdate.PublishResult
	failAt          int
	failErr         error
	calls           int
	resolveCalls    int
	resolveFailAt   int
	resolveFailErr  error
	resolvedZones   map[string]string
	resolvedLogical []string
	publishedZones  []string
}

func (f *fakeRotationPublisher) ResolveUpdateZone(_ context.Context, zone string) (string, error) {
	f.resolveCalls++
	f.resolvedLogical = append(f.resolvedLogical, zone)
	if f.resolveFailAt == f.resolveCalls {
		if f.resolveFailErr != nil {
			return "", f.resolveFailErr
		}
		return "", errors.New("synthetic update-zone resolution failure")
	}
	if resolved, ok := f.resolvedZones[zone]; ok {
		return resolved, nil
	}
	return zone, nil
}

func (f *fakeRotationPublisher) PublishIfAbsent(_ context.Context, zone string, _ dnsupdate.ExpectedTXT) (dnsupdate.PublishResult, error) {
	f.calls++
	f.publishedZones = append(f.publishedZones, zone)
	*f.events = append(*f.events, fmt.Sprintf("publish-%d", f.calls))
	if f.failAt == f.calls {
		if f.failErr != nil {
			return 0, f.failErr
		}
		return 0, errors.New("synthetic DNS publication failure")
	}
	if f.calls <= len(f.results) {
		return f.results[f.calls-1], nil
	}
	return dnsupdate.PublishCreated, nil
}

type fakeRotationProof struct {
	events *[]string
	calls  int
	failAt int
}

func (f *fakeRotationProof) ProveAll(_ context.Context, records []dnsupdate.ExpectedTXT) error {
	f.calls++
	*f.events = append(*f.events, fmt.Sprintf("prove-%d", f.calls))
	if len(records) == 0 {
		return errors.New("missing proof records")
	}
	if f.failAt == f.calls {
		return errors.New("synthetic DNS proof failure")
	}
	return nil
}

type failAfterMutationWriter struct{ writes int }

func (w *failAfterMutationWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("synthetic output failure")
}

type forbiddenRandom struct{ reads int }

func (r *forbiddenRandom) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("resume generated replacement keys")
}

func TestDKIM2ManualRotationExactOrderAndClosedOutcome(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	}), &cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	publisher := &fakeRotationPublisher{events: events}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		*events = append(*events, "open-publisher")
		return publisher, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) {
		*events = append(*events, "open-proof")
		return proof, nil
	}
	result, err := manager.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := []string{"load-current", "load-history", "stage", "open-publisher", "open-proof", "publish-1", "publish-2", "prove-1", "load-pending", "prove-2", "commit-switch", "load-pending"}
	if strings.Join(*events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", *events, want)
	}
	if result.DKIM2Outcome != DKIM2OutcomeActivated || publisher.calls != 2 || proof.calls != 2 {
		t.Fatalf("result=%#v publish=%d proof=%d", result, publisher.calls, proof.calls)
	}
}

func TestDKIM2ManualRotationCompletesForEachExactAlgorithmSet(t *testing.T) {
	sets := map[string][]dkim2model.Algorithm{
		"rsa":     {dkim2model.AlgorithmRSASHA256},
		"ed25519": {dkim2model.AlgorithmEd25519SHA256},
		"both":    {dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256},
	}
	for name, algorithms := range sets {
		t.Run(name, func(t *testing.T) {
			manager, repository, events := newRotationHarness(t, rotationGeneration(t, algorithms),
				&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
			defer repository.close()
			publisher := &fakeRotationPublisher{events: events}
			manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
			manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
			result, err := manager.Run()
			if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || publisher.calls != len(algorithms) {
				t.Fatalf("result=%#v publications=%d err=%v", result, publisher.calls, err)
			}
		})
	}
}

func TestDKIM2ManualRotationUpdateZoneFailureStopsBeforeDNSWrite(t *testing.T) {
	manager, repository, events := newRotationHarness(t,
		rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	publisher := &fakeRotationPublisher{events: events, resolveFailAt: 1, resolveFailErr: dnsupdate.ErrPublishUncertain}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }

	result, err := manager.Run()
	if err == nil || result == nil || publisher.resolveCalls != 1 || publisher.calls != 0 || proof.calls != 0 ||
		repository.stageCalls != 1 || repository.commitCalls != 0 {
		t.Fatalf("result=%#v resolve=%d publish=%d proof=%d stage=%d commit=%d err=%v",
			result, publisher.resolveCalls, publisher.calls, proof.calls, repository.stageCalls, repository.commitCalls, err)
	}
}

func TestDKIM2PrepareOnlyStagesAndStopsBeforeDNSConstruction(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, PrepareOnly: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed")
		return nil, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { t.Fatal("proof constructed"); return nil, nil }
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeStaged {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if got := strings.Join(*events, ","); got != "load-current,load-history,stage" {
		t.Fatalf("events = %s", got)
	}
}

func TestDKIM2ManualRotationAuthorizesBeforeRepositoryOrRandomness(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Size: 2048})
	defer repository.close()
	random := &forbiddenRandom{}
	manager.random = random
	result, err := manager.Run()
	if err == nil || !errors.Is(err, errConfirmationRequired) || result != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(*events) != 0 || random.reads != 0 {
		t.Fatalf("pre-authorization events=%v random=%d", *events, random.reads)
	}
}

func TestDKIM2LifecycleCommandsFailClosedBeforeRepositoryAccessWhenAuthorizationContractIsIncomplete(t *testing.T) {
	for _, opts := range []*cli.Options{
		{Auto: true, Yes: true},
		{RetireGenerationSet: true, RetireGeneration: 1, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true},
		{RollbackFromGenerationSet: true, RollbackFromGeneration: 1, UpdateDNS: true, Yes: true},
	} {
		manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}), opts)
		manager.cfg.DKIM2.RotationEnabled = true
		if result, err := manager.Run(); err == nil || result != nil {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		if len(*events) != 0 || repository.stageCalls != 0 || repository.commitCalls != 0 {
			t.Fatalf("deferred command accessed repository: events=%v", *events)
		}
		repository.close()
	}
}

func TestDKIM2DryRunUsesNoWriterOrRepositoryMutation(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, DryRun: true, Size: 2048})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed")
		return nil, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { t.Fatal("proof constructed"); return nil, nil }
	var output bytes.Buffer
	manager.out = &output
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun || repository.stageCalls != 0 {
		t.Fatalf("result=%#v stage=%d err=%v", result, repository.stageCalls, err)
	}
	if got := strings.Join(*events, ","); got != "load-current,load-history" {
		t.Fatalf("events = %s", got)
	}
	if !strings.Contains(output.String(), "apply creates new random keys") {
		t.Fatalf("dry-run output = %q", output.String())
	}
}

func TestDKIM2DryRunFollowedByApplyReloadsFreshProjections(t *testing.T) {
	manager, repository, events := newRotationHarness(t,
		rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, DryRun: true, Size: 2048})
	defer repository.close()
	if result, err := manager.Run(); err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun {
		t.Fatalf("dry-run result=%#v err=%v", result, err)
	}
	manager.opts.DryRun = false
	manager.opts.Yes = true
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	if result, err := manager.Run(); err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated {
		t.Fatalf("apply result=%#v err=%v", result, err)
	}
	loads, histories := 0, 0
	for _, event := range *events {
		if event == "load-current" {
			loads++
		}
		if event == "load-history" {
			histories++
		}
	}
	if loads != 2 || histories != 2 || repository.stageCalls != 1 {
		t.Fatalf("fresh projections load-current=%d history=%d stage=%d events=%v", loads, histories, repository.stageCalls, *events)
	}
}

func TestDKIM2ResumeUsesStoredCandidateWithoutRandomnessAndReconcilesPartialDNS(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Rotate: true, ResumeGenerationSet: true, ResumeGeneration: 2, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	repository.pending = candidate
	repository.observed = 1
	*events = nil
	random := &forbiddenRandom{}
	manager.random = random
	publisher := &fakeRotationPublisher{events: events, results: []dnsupdate.PublishResult{dnsupdate.PublishAlreadyPresent, dnsupdate.PublishCreated}}
	proof := &fakeRotationProof{events: events}
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		*events = append(*events, "open-publisher")
		return publisher, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) {
		*events = append(*events, "open-proof")
		return proof, nil
	}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || random.reads != 0 || repository.stageCalls != 0 {
		t.Fatalf("result=%#v random=%d stage=%d err=%v", result, random.reads, repository.stageCalls, err)
	}
}

func TestDKIM2ResumeDryRunTruthfullyReportsStoredCandidate(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Rotate: true, ResumeGenerationSet: true, ResumeGeneration: 2, Domains: []string{"example.test"}, UpdateDNS: true, DryRun: true, Size: 2048})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	repository.pending, repository.observed = candidate, 1
	*events = nil
	random := &forbiddenRandom{}
	manager.random = random
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed")
		return nil, nil
	}
	var output bytes.Buffer
	manager.out = &output
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeDryRun || random.reads != 0 ||
		!strings.Contains(output.String(), "apply reuses stored candidate") {
		t.Fatalf("result=%#v output=%q random=%d err=%v", result, output.String(), random.reads, err)
	}
}

func TestDKIM2ResumeRejectsMismatchedExplicitKeyTypeBeforeDNSOrMutation(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Rotate: true, ResumeGenerationSet: true, ResumeGeneration: 2, Domains: []string{"example.test"},
			UpdateDNS: true, Yes: true, Size: 2048, KeyType: "rsa"})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	repository.pending, repository.observed = candidate, 1
	*events = nil
	random := &forbiddenRandom{}
	manager.random = random
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed for mismatched resume keytype")
		return nil, nil
	}
	result, err := manager.Run()
	if err == nil || result != nil && result.DKIM2Outcome == DKIM2OutcomeActivated || random.reads != 0 ||
		repository.stageCalls != 0 || repository.commitCalls != 0 {
		t.Fatalf("result=%#v random=%d stage=%d commit=%d err=%v", result, random.reads, repository.stageCalls, repository.commitCalls, err)
	}
}

func TestDKIM2ResumeRejectsSameDomainDifferentBindingIdentity(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "configured", tenant: "tenant-test", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "example.test", suffix: "foreign", tenant: "other-tenant", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
	})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Rotate: true, ResumeGenerationSet: true, ResumeGeneration: 2, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "other-tenant", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	repository.pending, repository.observed = candidate, 1
	*events = nil
	if result, runErr := manager.Run(); runErr == nil || result != nil && result.DKIM2Outcome == DKIM2OutcomeActivated {
		t.Fatalf("foreign binding resume result=%#v err=%v", result, runErr)
	}
}

func TestDKIM2AlreadyActivatedResumeValidatesRequestedBindingBeforeSuccess(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, _ := newRotationHarness(t, current,
		&cli.Options{Rotate: true, ResumeGenerationSet: true, ResumeGeneration: 2, Domains: []string{"other.example"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := generationWithState(candidate, dkim2model.DatasetStateCommitted)
	_ = candidate.Close()
	if err != nil {
		t.Fatal(err)
	}
	repository.pending, repository.observed = committed, 2
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeAlreadyActivated {
		t.Fatalf("wrong-domain resume result=%#v err=%v", result, err)
	}
}

func TestDKIM2RotationReconcilesLostStageAndActivationResponses(t *testing.T) {
	for _, lost := range []string{"stage", "activation"} {
		t.Run(lost, func(t *testing.T) {
			manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
				&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
			defer repository.close()
			repository.stageLost = lost == "stage"
			repository.activationLost = lost == "activation"
			publisher := &fakeRotationPublisher{events: events}
			proof := &fakeRotationProof{events: events}
			manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) { return publisher, nil }
			manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return proof, nil }
			result, err := manager.Run()
			if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated {
				t.Fatalf("result=%#v err=%v events=%v", result, err, *events)
			}
		})
	}
}

func TestDKIM2LostRootCommitRequiresExplicitResumeBeforePointerSwitch(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	repository.commitOnlyLost = true
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeActivated || repository.observed != 1 || repository.commitCalls != 1 {
		t.Fatalf("first run result=%#v observed=%d commits=%d err=%v", result, repository.observed, repository.commitCalls, err)
	}

	repository.commitOnlyLost = false
	manager.opts.ResumeGenerationSet, manager.opts.ResumeGeneration = true, 2
	result, err = manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || repository.observed != 2 || repository.commitCalls != 2 {
		t.Fatalf("resume result=%#v observed=%d commits=%d err=%v", result, repository.observed, repository.commitCalls, err)
	}
}

func TestDKIM2SecondPublisherCannotPlanPastExistingCandidate(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, PrepareOnly: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	if _, err := manager.Run(); err != nil {
		t.Fatal(err)
	}
	random := &forbiddenRandom{}
	manager.random = random
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeStaged {
		t.Fatalf("second publisher result=%#v err=%v", result, err)
	}
	if repository.stageCalls != 1 || random.reads != 0 {
		t.Fatalf("second publisher stage=%d random=%d", repository.stageCalls, random.reads)
	}
}

func TestDKIM2LostStageResponseNeverAdoptsConcurrentForeignCandidate(t *testing.T) {
	current := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	history, _ := repository.LoadRetainedHistory(context.Background(), 8)
	foreign, err := dkim2model.PlanRotation(dkim2model.RotationPlan{Current: current, NextGeneration: 2,
		TenantID: "tenant-test", Domain: "example.test", Use: dkim2model.ProfileUseOriginator,
		RSABits: 2048, AllocationAttempts: 16, Random: rand.Reader, History: history})
	if err != nil {
		t.Fatal(err)
	}
	repository.foreignPending = foreign
	repository.fail["stage"] = dkim2store.ErrUnavailable
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		t.Fatal("publisher constructed after foreign staging readback")
		return nil, nil
	}
	result, err := manager.Run()
	if err == nil || result.DKIM2Outcome == DKIM2OutcomeActivated || repository.stageCalls != 1 {
		t.Fatalf("result=%#v stage=%d err=%v events=%v", result, repository.stageCalls, err, *events)
	}
}

func TestDKIM2RotationFailsClosedAtEveryExternalPhase(t *testing.T) {
	for _, phase := range []string{"load-current", "load-history", "stage", "publisher", "proof", "publish", "first-proof", "reread", "second-proof", "commit", "readback"} {
		t.Run(phase, func(t *testing.T) {
			manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
				&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
			defer repository.close()
			repository.fail = map[string]error{}
			publisher := &fakeRotationPublisher{events: events}
			proof := &fakeRotationProof{events: events}
			switch phase {
			case "load-current", "load-history", "stage":
				repository.fail[phase] = errors.New("synthetic phase failure")
			case "reread":
				repository.fail["load-pending"] = errors.New("synthetic phase failure")
			case "commit":
				repository.fail["commit-switch"] = errors.New("synthetic phase failure")
			case "readback":
				repository.fail["load-pending"] = nil // replaced after commit by hook below
			case "publish":
				publisher.failAt = 1
			case "first-proof":
				proof.failAt = 1
			case "second-proof":
				proof.failAt = 2
			}
			manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
				if phase == "publisher" {
					return nil, errors.New("synthetic constructor failure")
				}
				return publisher, nil
			}
			manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) {
				if phase == "proof" {
					return nil, errors.New("synthetic constructor failure")
				}
				return proof, nil
			}
			if phase == "readback" {
				repository.failAfterCommit = true
			}
			if result, err := manager.Run(); err == nil || result == nil || result.DKIM2Outcome == DKIM2OutcomeActivated {
				t.Fatalf("result=%#v err=%v events=%v", result, err, *events)
			}
		})
	}
}

func TestDKIM2RotationReportingFailureDoesNotTurnCompletedMutationIntoRetry(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	writer := &failAfterMutationWriter{}
	manager.out = writer
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeActivated || !result.ReportingFailed || repository.observed != 2 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestDKIM2PrepareOnlyReportingFailureDoesNotTurnStagingIntoRetry(t *testing.T) {
	manager, repository, _ := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, PrepareOnly: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.out = &failAfterMutationWriter{}
	result, err := manager.Run()
	if err != nil || result.DKIM2Outcome != DKIM2OutcomeStaged || !result.ReportingFailed || repository.stageCalls != 1 {
		t.Fatalf("result=%#v stage=%d err=%v", result, repository.stageCalls, err)
	}
}

func TestDKIM2ManualRotationPreservesUnrelatedDomainExactly(t *testing.T) {
	current := rotationGenerationBindings(t, []rotationBindingSpec{
		{domain: "example.test", suffix: "target", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}},
		{domain: "other.example", suffix: "other", algorithms: []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256}},
	})
	before, found := current.CredentialByDomainSelector("other.example", "selector-other-0")
	if !found {
		t.Fatal("unrelated baseline credential missing")
	}
	manager, repository, events := newRotationHarness(t, current,
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	if _, err := manager.Run(); err != nil {
		t.Fatal(err)
	}
	after, found := repository.pending.CredentialByDomainSelector("other.example", "selector-other-0")
	if !found || after.ProfileID() != before.ProfileID() || after.Algorithm() != before.Algorithm() ||
		after.HandleID() != before.HandleID() || !bytes.Equal(after.PublicSPKIDER(), before.PublicSPKIDER()) {
		t.Fatal("unrelated domain was not logically preserved")
	}
	policy, found := exactPolicy(repository.pending, "tenant-test", "other.example", dkim2model.ProfileUseOriginator)
	if !found || policy.Status() != dkim2model.RecordStatusActive || policy.Rollout() != dkim2model.RolloutEnforce {
		t.Fatal("unrelated policy was not logically preserved")
	}
}

func TestDKIM2RotationOutputIsBoundedAndSecretSafe(t *testing.T) {
	manager, repository, events := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	manager.newRotationPublisher = func(*config.Config) (dkim2RotationPublisher, error) {
		return &fakeRotationPublisher{events: events}, nil
	}
	manager.newRotationProof = func(*config.Config) (dkim2RotationProof, error) { return &fakeRotationProof{events: events}, nil }
	var output bytes.Buffer
	manager.out = &output
	if _, err := manager.Run(); err != nil {
		t.Fatal(err)
	}
	if output.Len() > 160 {
		t.Fatalf("unbounded output length = %d", output.Len())
	}
	for _, marker := range []string{"example.test", "selector-", "handle-", "BEGIN", "TSIG", "ldap", "127.0.0"} {
		if strings.Contains(output.String(), marker) {
			t.Fatalf("output contains protected marker %q: %q", marker, output.String())
		}
	}
}

func TestDKIM2RotationErrorsDoNotPropagateProtectedBackendMarkers(t *testing.T) {
	manager, repository, _ := newRotationHarness(t, rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Rotate: true, Domains: []string{"example.test"}, UpdateDNS: true, Yes: true, Size: 2048})
	defer repository.close()
	marker := "handle-secret-marker TSIG-secret bind-password dn=protected"
	repository.fail["load-current"] = errors.New(marker)
	_, err := manager.Run()
	if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "handle-secret") || strings.Contains(err.Error(), "bind-password") {
		t.Fatalf("unsafe error = %q", err)
	}
}

func newRotationHarness(t *testing.T, current *dkim2model.Generation, opts *cli.Options) (*DKIM2Manager, *fakeRotationRepository, *[]string) {
	t.Helper()
	journalDirectory := t.TempDir()
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	events := &[]string{}
	repository := &fakeRotationRepository{current: current, observed: current.Number(), events: events, fail: map[string]error{}, retained: map[uint64]*dkim2model.Generation{}}
	cfg := &config.Config{Global: config.GlobalConfig{Mode: types.ModeDKIM2, KeyType: "both"},
		DKIM2: config.DKIM2Config{TenantID: "tenant-test", ProfileUse: "originator", Rollout: "enforce", Compatibility: "strict",
			HistoryLimit: 8, MaxCampaignBindings: 16, MaxGenerationEntries: 1024,
			MaxAttributeBytes: 64 << 10, MaxDatasetBytes: 4 << 20, MaxLDAPRequests: 4096,
			MaxLDAPBytes: 8 << 20, MaxRetainedRootVisits: 32, IdentifierAllocationAttempts: 32,
			PublicationReadbackAttempts: 8, PublicationReadbackIntervalMillis: 1, LDAPSearchTimeLimitSeconds: 30,
			LDAPOperationTimeoutSeconds: 30, AuthorityPasswordMaxBytes: 1024,
			RotateAfterDays: 365, MaxClockSkewSeconds: 300, RunTimeoutSeconds: 30, DNSQueryTimeoutSeconds: 1,
			ProofPollIntervalSeconds: 1, ProofMaxAttempts: 2, RetirementMinOverlapSeconds: 7 * 24 * 60 * 60,
			Retention: config.DKIM2RetentionConfig{Enabled: true, MaxGenerations: 6, MinRollbackGenerations: 2,
				MaxDeleteBatch: 2, JournalFile: journalDirectory + "/retention-plan.json", MaxJournalBytes: 4096}},
		DNS: config.DNSConfig{PrimaryNameserver: "127.0.0.1:53", RecursiveNameserver: "127.0.0.2:53", TTL: 300,
			TSIGKeyName: "synthetic-key", TSIGKeyFile: "/synthetic/key", Algorithm: "hmac_sha256"}, KeyType: types.DKIMKeyTypeBoth}
	manager := &DKIM2Manager{cfg: cfg, opts: opts, repository: repository, rotationRepository: repository,
		campaignRepository: repository,
		random:             rand.Reader, in: strings.NewReader("yes\n"), out: io.Discard, now: func() time.Time { return time.Now().UTC() }}
	return manager, repository, events
}

func rotationGeneration(t *testing.T, algorithms []dkim2model.Algorithm) *dkim2model.Generation {
	return rotationGenerationBindings(t, []rotationBindingSpec{{domain: "example.test", suffix: "test", algorithms: algorithms}})
}

type rotationBindingSpec struct {
	domain     string
	suffix     string
	tenant     string
	use        dkim2model.ProfileUse
	algorithms []dkim2model.Algorithm
}

func rotationGenerationBindings(t *testing.T, bindings []rotationBindingSpec) *dkim2model.Generation {
	t.Helper()
	builder, err := dkim2model.NewBuilder(1, dkim2model.DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	for _, binding := range bindings {
		if binding.tenant == "" {
			binding.tenant = "tenant-test"
		}
		if binding.use == "" {
			binding.use = dkim2model.ProfileUseOriginator
		}
		profile, profileErr := dkim2model.NewProfile(1, "profile-"+binding.suffix, binding.domain, dkim2model.RecordStatusActive, time.Time{}, time.Time{})
		if profileErr != nil {
			t.Fatal(profileErr)
		}
		var credentials []dkim2model.Credential
		var materials []*dkim2model.KeyMaterial
		for index, algorithm := range binding.algorithms {
			pair, pairErr := dkim2model.GenerateKeyPair(algorithm, 2048, nil)
			if pairErr != nil {
				t.Fatal(pairErr)
			}
			handle := fmt.Sprintf("handle-%s-%d", binding.suffix, index)
			credential, credentialErr := dkim2model.NewCredential(1, profile.ID(), fmt.Sprintf("selector-%s-%d", binding.suffix, index), algorithm, pair.PublicSPKIDER(), handle)
			material, materialErr := dkim2model.NewKeyMaterial(1, binding.tenant, binding.domain, binding.use, handle, pair)
			_ = pair.Close()
			if credentialErr != nil || materialErr != nil {
				closeMaterials(materials)
				t.Fatal(errors.Join(credentialErr, materialErr))
			}
			credentials = append(credentials, credential)
			materials = append(materials, material)
		}
		policy, policyErr := dkim2model.NewPolicy(1, binding.tenant, binding.domain, binding.use, profile.ID(),
			dkim2model.RecordStatusActive, dkim2model.RolloutEnforce, dkim2model.CompatibilityStrict, "")
		if policyErr == nil {
			policyErr = builder.AddProfileWithKeys(profile, credentials, policy, materials)
		}
		closeMaterials(materials)
		if policyErr != nil {
			t.Fatal(policyErr)
		}
	}
	generation, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return generation
}
