package app

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
)

// TestDKIM2CreateResumeStoredCandidate reproduces a completed stage followed by process loss before activation.
func TestDKIM2CreateResumeStoredCandidate(t *testing.T) {
	for _, dry := range []bool{true, false} {
		t.Run(map[bool]string{true: "dry-run", false: "publish"}[dry], func(t *testing.T) {
			manager, repository, _ := newRotationHarness(t,
				rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
				&cli.Options{Create: true, Domains: []string{"example.test", "other.example"}, KeyType: "ed25519", Size: 2048, Yes: true})
			defer repository.close()
			manager.cfg.DKIM2.RotationEnabled = true
			manager.cfg.DKIM2.ProfileUse = "ordinary_transit"
			repository.fail["commit-switch"] = errors.New("synthetic process loss")
			if err := manager.create(context.Background()); err == nil || repository.pending == nil || repository.campaignMetadata == nil {
				t.Fatal("fixture did not leave one complete native staging candidate")
			}
			stored, err := repository.pending.Clone()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stored.Close() }()
			metadata := *repository.campaignMetadata
			stageCalls, commitCalls := repository.stageCalls, repository.commitCalls
			delete(repository.fail, "commit-switch")
			manager.opts.ResumeGenerationSet, manager.opts.ResumeGeneration = true, stored.Number()
			manager.opts.DryRun = dry
			manager.random = bytes.NewReader(nil)
			if _, err := manager.Run(); err != nil {
				t.Fatalf("resume complete native create: %v", err)
			}
			if repository.stageCalls != stageCalls || !metadata.ExactEqual(*repository.campaignMetadata) {
				t.Fatal("resume restaged or replaced the protected operation")
			}
			if dry {
				if repository.commitCalls != commitCalls || !repository.pending.Equivalent(stored) || repository.observed != repository.current.Number() {
					t.Fatal("dry-run mutated the staged candidate or current")
				}
				return
			}
			committed, err := cloneGenerationWithState(stored, dkim2model.DatasetStateCommitted)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = committed.Close() }()
			if repository.commitCalls != commitCalls+1 || !repository.pending.Equivalent(committed) || repository.observed != stored.Number() {
				t.Fatal("resume did not commit the exact stored candidate once")
			}
		})
	}
}

// newCreateResumeHarness persists a complete create operation and then removes every generation/write helper from recovery.
func newCreateResumeHarness(t *testing.T, keyType string) (*DKIM2Manager, *fakeRotationRepository, *countingAppReader) {
	t.Helper()
	manager, repository, _ := newRotationHarness(t,
		rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}),
		&cli.Options{Create: true, Domains: []string{"example.test", "other.example"}, KeyType: keyType, Size: 2048, Yes: true})
	t.Cleanup(repository.close)
	manager.cfg.DKIM2.RotationEnabled, manager.cfg.DKIM2.ProfileUse = true, "ordinary_transit"
	repository.fail["commit-switch"] = errors.New("synthetic interruption")
	if err := manager.create(context.Background()); err == nil || repository.pending == nil || repository.campaignMetadata == nil {
		t.Fatal("expected complete protected staging fixture")
	}
	delete(repository.fail, "commit-switch")
	repository.stageCalls, repository.commitCalls = 0, 0
	manager.opts.ResumeGenerationSet, manager.opts.ResumeGeneration = true, repository.pending.Number()
	random := &countingAppReader{}
	manager.random = random
	return manager, repository, random
}

// TestDKIM2CreateResumeRejectsUnrelatedIntent requires exact command, source, retained shape, and metadata before any mutation.
func TestDKIM2CreateResumeRejectsUnrelatedIntent(t *testing.T) {
	tests := map[string]func(*DKIM2Manager, *fakeRotationRepository){
		"missing-domain": func(m *DKIM2Manager, _ *fakeRotationRepository) { m.opts.Domains = m.opts.Domains[:1] },
		"extra-domain": func(m *DKIM2Manager, _ *fakeRotationRepository) {
			m.opts.Domains = append(m.opts.Domains, "extra.example")
		},
		"duplicate-domain": func(m *DKIM2Manager, _ *fakeRotationRepository) {
			m.opts.Domains = []string{"example.test", "example.test"}
		},
		"different-tenant":       func(m *DKIM2Manager, _ *fakeRotationRepository) { m.cfg.DKIM2.TenantID = "other-tenant" },
		"different-use":          func(m *DKIM2Manager, _ *fakeRotationRepository) { m.cfg.DKIM2.ProfileUse = "delivery_status" },
		"different-algorithms":   func(m *DKIM2Manager, _ *fakeRotationRepository) { m.opts.KeyType = "rsa" },
		"different-feedback":     func(m *DKIM2Manager, _ *fakeRotationRepository) { m.cfg.DKIM2.FeedbackRouteID = "new-feedback" },
		"binding-budget":         func(m *DKIM2Manager, _ *fakeRotationRepository) { m.cfg.DKIM2.MaxCampaignBindings = 1 },
		"bootstrap":              func(m *DKIM2Manager, _ *fakeRotationRepository) { m.opts.ResumeGeneration = 1 },
		"different-generation":   func(m *DKIM2Manager, _ *fakeRotationRepository) { m.opts.ResumeGeneration++ },
		"no-native-authorities":  func(m *DKIM2Manager, _ *fakeRotationRepository) { m.campaignRepository = nil },
		"native-disabled":        func(m *DKIM2Manager, _ *fakeRotationRepository) { m.cfg.DKIM2.RotationEnabled = false },
		"legacy-metadata":        func(_ *DKIM2Manager, r *fakeRotationRepository) { r.campaignMetadata = nil },
		"uninitialized-metadata": func(_ *DKIM2Manager, r *fakeRotationRepository) { r.campaignMetadata = &dkim2model.CandidateMetadata{} },
		"partial-history":        func(_ *DKIM2Manager, r *fakeRotationRepository) { r.historyIncomplete = true },
		"history-read-failed": func(_ *DKIM2Manager, r *fakeRotationRepository) {
			r.fail["load-history"] = errors.New("synthetic failure")
		},
		"source-read-failed": func(_ *DKIM2Manager, r *fakeRotationRepository) {
			r.fail["load-retained"] = errors.New("synthetic failure")
		},
		"later-current":          func(_ *DKIM2Manager, r *fakeRotationRepository) { r.observed = r.pending.Number() + 1 },
		"additional-generation":  nil,
		"changed-source-content": nil,
	}
	for name, change := range tests {
		for _, dry := range []bool{true, false} {
			t.Run(name+map[bool]string{true: "/dry", false: "/apply"}[dry], func(t *testing.T) {
				manager, repository, random := newCreateResumeHarness(t, "ed25519")
				switch name {
				case "additional-generation":
					builder, err := repository.pending.NextBuilder(repository.pending.Number()+1, dkim2model.DatasetStateStaging)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = builder.Close() }()
					next, err := builder.Build()
					if err != nil {
						t.Fatal(err)
					}
					repository.retained[next.Number()] = next
				case "changed-source-content":
					_ = repository.current.Close()
					repository.current = rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
				default:
					change(manager, repository)
				}
				manager.opts.DryRun, manager.opts.UpdateDNS = dry, true
				dnsCalls := 0
				manager.dns = fakeDKIM2DNSUpdater{add: func(string, string, string, string) error { dnsCalls++; return nil }}
				if _, err := manager.Run(); err == nil {
					t.Fatal("unrelated or incomplete create recovery was accepted")
				}
				if repository.stageCalls != 0 || repository.commitCalls != 0 || random.reads != 0 || dnsCalls != 0 {
					t.Fatal("rejected recovery generated, staged, committed, or published")
				}
			})
		}
	}
}

// rewriteCreateResumeRecords makes a valid but semantically different committed candidate for negative tests.
func rewriteCreateResumeRecords(t *testing.T, repository *fakeRotationRepository, change func([]dkim2model.Profile, []dkim2model.Policy)) {
	t.Helper()
	profiles, policies := repository.pending.Profiles(), repository.pending.Policies()
	change(profiles, policies)
	materials := repository.pending.KeyMaterials()
	defer closeMaterials(materials)
	candidate, err := dkim2model.NewGenerationWithState(repository.pending.Number(), repository.pending.State(),
		repository.pending.Handles(), profiles, repository.pending.Credentials(), policies, materials)
	if err != nil {
		t.Fatal(err)
	}
	replaceCreateResumeCandidate(t, repository, candidate)
}

// replaceCreateResumeCandidate rebinds an otherwise valid stored operation to its exact synthetic contents.
func replaceCreateResumeCandidate(t *testing.T, repository *fakeRotationRepository, candidate *dkim2model.Generation) {
	t.Helper()
	var metadata dkim2model.CandidateMetadata
	err := repository.campaignMetadata.WithLDAPValues(func(operation string, _ []byte) error {
		var err error
		metadata, err = dkim2model.NewCandidateMetadata(operation, repository.current.Number(), candidate)
		return err
	})
	if err != nil {
		_ = candidate.Close()
		t.Fatal(err)
	}
	_ = repository.pending.Close()
	repository.pending, repository.campaignMetadata = candidate, &metadata
}

// TestDKIM2CreateResumeRejectsCommittedContentChanges proves that valid metadata is not sufficient authorization.
func TestDKIM2CreateResumeRejectsCommittedContentChanges(t *testing.T) {
	for _, name := range []string{"new-active", "new-validity", "new-observe", "old-profile-policy", "old-key"} {
		t.Run(name, func(t *testing.T) {
			manager, repository, random := newCreateResumeHarness(t, "ed25519")
			if name == "old-key" {
				// Replace the source's existing key while leaving every requested addition intact.
				other := rotationGeneration(t, []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256})
				defer func() { _ = other.Close() }()
				builder, err := other.NextBuilder(repository.pending.Number(), repository.pending.State())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = builder.Close() }()
				for _, policy := range repository.pending.Policies() {
					if policy.Use() != dkim2model.ProfileUseOrdinaryTransit {
						continue
					}
					profile, _ := repository.pending.ProfileByID(policy.ProfileID())
					credentials := credentialsForProfile(repository.pending, profile.ID())
					var materials []*dkim2model.KeyMaterial
					for _, credential := range credentials {
						material, _ := repository.pending.KeyMaterialByHandle(credential.HandleID())
						materials = append(materials, material)
					}
					err := builder.AddProfileWithKeys(profile, credentials, policy, materials)
					closeMaterials(materials)
					if err != nil {
						t.Fatal(err)
					}
				}
				candidate, err := builder.Build()
				if err != nil {
					t.Fatal(err)
				}
				replaceCreateResumeCandidate(t, repository, candidate)
			} else {
				rewriteCreateResumeRecords(t, repository, func(profiles []dkim2model.Profile, policies []dkim2model.Policy) {
					for index, profile := range profiles {
						if profile.Status() == dkim2model.RecordStatusDisabled && name == "new-active" {
							profiles[index], _ = profile.WithStatus(dkim2model.RecordStatusActive)
						} else if profile.Status() == dkim2model.RecordStatusDisabled && name == "new-validity" {
							start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
							profiles[index], _ = dkim2model.NewProfile(profile.Generation(), profile.ID(), profile.SigningDomain(), profile.Status(), start, start.Add(time.Hour))
						} else if profile.Status() == dkim2model.RecordStatusActive && name == "old-profile-policy" {
							profiles[index], _ = profile.WithStatus(dkim2model.RecordStatusDisabled)
						}
					}
					for index, policy := range policies {
						status, rollout := policy.Status(), policy.Rollout()
						if policy.Use() == dkim2model.ProfileUseOrdinaryTransit && name == "new-observe" {
							rollout = dkim2model.RolloutObserve
						}
						if policy.Use() == dkim2model.ProfileUseOriginator && name == "old-profile-policy" {
							status, rollout = dkim2model.RecordStatusDisabled, dkim2model.RolloutOff
						}
						policies[index], _ = dkim2model.NewPolicy(policy.Generation(), policy.TenantID(), policy.SigningDomain(), policy.Use(), policy.ProfileID(), status, rollout, policy.Compatibility(), policy.FeedbackRouteID())
					}
				})
			}
			if _, err := manager.Run(); err == nil {
				t.Fatal("altered candidate passed exact create comparison")
			}
			if repository.stageCalls != 0 || repository.commitCalls != 0 || random.reads != 0 {
				t.Fatal("rejected content change mutated native state")
			}
		})
	}
}

// createResumeReadbackRepository injects one bounded readback transition without changing the native repository contract.
type createResumeReadbackRepository struct {
	*fakeRotationRepository
	loads  int
	change func(int)
}

// LoadPending injects the selected lifecycle event before returning ordinary detached evidence.
func (r *createResumeReadbackRepository) LoadPending(ctx context.Context, number uint64, limit int) (*dkim2store.PreparedGeneration, error) {
	r.loads++
	if r.change != nil {
		r.change(r.loads)
	}
	return r.fakeRotationRepository.LoadPending(ctx, number, limit)
}

// TestDKIM2CreateResumeReadbackFences detects current drift and replacement operation identities before committing.
func TestDKIM2CreateResumeReadbackFences(t *testing.T) {
	for _, name := range []string{"current", "operation", "unavailable"} {
		t.Run(name, func(t *testing.T) {
			manager, repository, random := newCreateResumeHarness(t, "ed25519")
			wrapper := &createResumeReadbackRepository{fakeRotationRepository: repository}
			wrapper.change = func(load int) {
				if load != 2 {
					return
				}
				switch name {
				case "current":
					repository.observed++
				case "operation":
					operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{0x65}, 16)))
					if err != nil {
						t.Fatal(err)
					}
					metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, repository.current.Number(), repository.pending)
					if err != nil {
						t.Fatal(err)
					}
					repository.campaignMetadata = &metadata
				case "unavailable":
					repository.fail["load-pending"] = errors.New("synthetic readback outage")
				}
			}
			manager.campaignRepository = wrapper
			if _, err := manager.Run(); err == nil {
				t.Fatal("changed publication evidence was accepted")
			}
			if repository.stageCalls != 0 || repository.commitCalls != 0 || random.reads != 0 {
				t.Fatal("drifted readback caused a mutation")
			}
		})
	}
}

// TestDKIM2CreateResumeDNSFailureRetry publishes only exact new keys and reuses an already-current operation.
func TestDKIM2CreateResumeDNSFailureRetry(t *testing.T) {
	manager, repository, random := newCreateResumeHarness(t, "both")
	manager.opts.UpdateDNS = true
	expected := map[string]string{}
	for _, policy := range repository.pending.Policies() {
		if policy.Use() != dkim2model.ProfileUseOrdinaryTransit {
			continue
		}
		for _, credential := range credentialsForProfile(repository.pending, policy.ProfileID()) {
			expected[policy.SigningDomain()+"/"+credential.Selector()] = dnsRecord(credential)
		}
	}
	var published []string
	fail := true
	manager.dns = fakeDKIM2DNSUpdater{add: func(domain, selector, content, subdomain string) error {
		key := domain + "/" + selector
		if expected[key] != content || subdomain != "" || repository.observed != repository.pending.Number() {
			t.Fatal("DNS publication escaped exact new committed scope")
		}
		published = append(published, key)
		if fail && len(published) == 2 {
			return errors.New("synthetic partial DNS failure")
		}
		return nil
	}}
	if _, err := manager.Run(); err == nil {
		t.Fatal("partial DNS update was reported complete")
	}
	if repository.commitCalls != 1 || repository.observed != repository.pending.Number() {
		t.Fatal("DNS failure lost the already committed candidate")
	}
	metadata := *repository.campaignMetadata
	fail = false
	if _, err := manager.Run(); err != nil {
		t.Fatal(err)
	}
	if repository.commitCalls != 1 || repository.stageCalls != 0 || random.reads != 0 || !metadata.ExactEqual(*repository.campaignMetadata) {
		t.Fatal("DNS recovery replaced or recommitted the current operation")
	}
	if len(published) != 6 || len(slices.Compact(slices.Sorted(slices.Values(published)))) != len(expected) {
		t.Fatal("DNS retry did not cover exactly the new selector set")
	}
	manager.opts.DryRun = true
	before := len(published)
	if _, err := manager.Run(); err != nil || len(published) != before {
		t.Fatal("already-current dry-run failed or wrote DNS", err)
	}
}

// TestDKIM2CreateResumeCommitRecovery distinguishes committed-unreachable, lost-success, and uncertain outcomes.
func TestDKIM2CreateResumeCommitRecovery(t *testing.T) {
	for _, name := range []string{"committed-unreachable", "lost-success", "lost-before-switch", "final-readback-failure"} {
		t.Run(name, func(t *testing.T) {
			manager, repository, random := newCreateResumeHarness(t, "ed25519")
			switch name {
			case "committed-unreachable":
				committed, err := cloneGenerationWithState(repository.pending, dkim2model.DatasetStateCommitted)
				if err != nil {
					t.Fatal(err)
				}
				_ = repository.pending.Close()
				repository.pending = committed
			case "lost-success":
				repository.activationLost = true
			case "lost-before-switch":
				repository.commitOnlyLost = true
			case "final-readback-failure":
				repository.failAfterCommit = true
			}
			_, err := manager.Run()
			failure := name == "lost-before-switch" || name == "final-readback-failure"
			if (err != nil) != failure {
				t.Fatalf("unexpected recovery outcome: %v", err)
			}
			if repository.stageCalls != 0 || repository.commitCalls != 1 || random.reads != 0 {
				t.Fatal("commit recovery repeated a write or generated a key")
			}
			if failure {
				repository.commitOnlyLost, repository.failAfterCommit = false, false
				if _, err := manager.Run(); err != nil {
					t.Fatalf("explicit restart: %v", err)
				}
				if repository.observed != repository.pending.Number() {
					t.Fatal("restart did not recover native current")
				}
			}
		})
	}
}

// TestDKIM2CreateResumePreservesAutomaticScope keeps additive disabled work out of automatic key rotation.
func TestDKIM2CreateResumePreservesAutomaticScope(t *testing.T) {
	manager, repository, random := newCreateResumeHarness(t, "ed25519")
	manager.opts = &cli.Options{Auto: true, UpdateDNS: true, Yes: true, Size: 2048}
	if _, err := manager.Run(); err == nil {
		t.Fatal("automatic rotation accepted additive administrative work")
	}
	if repository.stageCalls != 0 || repository.commitCalls != 0 || random.reads != 0 {
		t.Fatal("automatic rejection mutated the administrative operation")
	}
}

// TestDKIM2CreateResumeAuthorizationAndDryRun defers TSIG access and every write until explicit validated recovery.
func TestDKIM2CreateResumeAuthorizationAndDryRun(t *testing.T) {
	manager, repository, random := newCreateResumeHarness(t, "ed25519")
	manager.opts.UpdateDNS, manager.opts.Yes = true, false
	if _, err := manager.Run(); !errors.Is(err, errConfirmationRequired) {
		t.Fatal("create resume bypassed existing write authorization")
	}
	manager.opts.DryRun = true
	if _, err := manager.Run(); err != nil {
		t.Fatalf("dry-run should not load the unavailable synthetic TSIG file: %v", err)
	}
	manager.opts.DryRun, manager.opts.Yes = false, true
	if _, err := manager.Run(); err == nil {
		t.Fatal("unavailable TSIG authentication was accepted")
	}
	if repository.stageCalls != 0 || repository.commitCalls != 0 || random.reads != 0 {
		t.Fatal("unauthorized, dry-run, or unauthenticated recovery mutated native state")
	}
}

// TestDKIM2CreateResumeCurrentChangesDuringDNS stops a partially published set when the protected current changes.
func TestDKIM2CreateResumeCurrentChangesDuringDNS(t *testing.T) {
	manager, repository, random := newCreateResumeHarness(t, "ed25519")
	manager.opts.UpdateDNS = true
	calls := 0
	manager.dns = fakeDKIM2DNSUpdater{add: func(string, string, string, string) error {
		calls++
		repository.observed++
		return nil
	}}
	if _, err := manager.Run(); err == nil || calls != 1 {
		t.Fatal("DNS publication continued after native current changed")
	}
	if repository.commitCalls != 1 || repository.stageCalls != 0 || random.reads != 0 {
		t.Fatal("current drift restaged, recommitted, or regenerated the operation")
	}
}
