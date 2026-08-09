package dkim2store

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const (
	storeFixedPrivatePKCS8Hex = "302e020100300506032b657004220420" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	storeFixedPublicSPKIHex = "302a300506032b6570032100" +
		"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
)

func FuzzLDAPV2EntryMapper(f *testing.F) {
	f.Add(byte(0), byte(0), "generation-1")
	f.Add(byte(4), byte(2), "selector")
	f.Add(byte(7), byte(5), "")
	f.Fuzz(func(t *testing.T, entryIndex, attributeIndex byte, replacement string) {
		if len(replacement) > 256 {
			t.Skip()
		}
		executor := newFakeExecutor(testBaseDN)
		repository := mustRepository(t, executor)
		generation := fixedStoreGeneration(t, 1, dkim2model.DatasetStateStaging)
		defer func() { _ = generation.Close() }()
		if err := repository.addCandidate(context.Background(), generation); err != nil {
			t.Fatalf("fixed LDAP fixture: %v", err)
		}
		root := repository.generationRoot(1)
		entries := make([]*ldap.Entry, 0, len(executor.entries))
		for _, entry := range executor.entries {
			if isAtOrBelow(entry.DN, root) {
				entries = append(entries, cloneEntry(entry))
			}
		}
		if len(entries) == 0 {
			t.Fatal("fixed LDAP fixture is empty")
		}
		target := entries[int(entryIndex)%len(entries)]
		if len(target.Attributes) > 0 {
			attribute := target.Attributes[int(attributeIndex)%len(target.Attributes)]
			setEntryAttribute(target, attribute.Name, []string{replacement})
		}
		mapped, err := mapGeneration(entries, 1, datasetStateStaging, root, testLimits())
		if err == nil {
			_ = mapped.Close()
		}
	})
}

func FuzzCanonicalGeneralizedTime(f *testing.F) {
	for _, seed := range []string{"20250701000000Z", "20250701000000.0Z", "20250701000000+0000", "", "20250230000000Z"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 128 {
			t.Skip()
		}
		parsed, err := parseGeneralizedTime([]byte(value))
		if err == nil && (parsed.Location() != time.UTC || parsed.Format(generalizedTimeLayout) != value) {
			t.Fatal("accepted noncanonical generalized time")
		}
	})
}

func TestRetainedHistoryLineageProperty(t *testing.T) {
	generation := fixedStoreGeneration(t, 1, dkim2model.DatasetStateCommitted)
	defer func() { _ = generation.Close() }()
	credential := generation.Credentials()[0]
	profile, found := generation.ProfileByID(credential.ProfileID())
	if !found {
		t.Fatal("fixed profile missing")
	}
	fact, err := dkim2model.NewLineageFact(
		1, "20250701000000Z", "tenant", profile.SigningDomain(), dkim2model.ProfileUseOriginator,
		credential.Selector(), credential.Algorithm(), credential.PublicSPKIDER(), credential.HandleID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewRetainedHistoryWithLineage(
		[]GenerationRoot{{Number: 1, State: dkim2model.DatasetStateCommitted}},
		[]string{credential.Selector()}, []string{credential.HandleID()},
		dkim2model.LineageHistory{Complete: true, Facts: []dkim2model.LineageFact{fact}},
	)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := history.LineageHistory()
	if err != nil || !projection.Complete || len(projection.Facts) != 1 {
		t.Fatalf("lineage projection = %#v, %v", projection, err)
	}
	if used, err := history.SelectorUsed(credential.Selector()); err != nil || !used {
		t.Fatalf("selector history = %t, %v", used, err)
	}
	if used, err := history.HandleUsed(credential.HandleID()); err != nil || !used {
		t.Fatalf("handle history = %t, %v", used, err)
	}
	if _, err := (RetainedHistory{Complete: false}).LineageHistory(); err == nil {
		t.Fatal("incomplete lineage was accepted")
	}

	// Exercise repository projection with the same fixed canonical DER fixture.
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	staging := fixedStoreGeneration(t, 1, dkim2model.DatasetStateStaging)
	defer func() { _ = staging.Close() }()
	if err := repository.Publish(context.Background(), 0, staging); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil || !loaded.Complete {
		t.Fatalf("repository lineage = %v, %v", loaded, err)
	}
}

func fixedStoreGeneration(t *testing.T, generation uint64, state dkim2model.DatasetState) *dkim2model.Generation {
	t.Helper()
	privateDER, err := hex.DecodeString(storeFixedPrivatePKCS8Hex)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateDER)
	publicDER, err := hex.DecodeString(storeFixedPublicSPKIHex)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(publicDER)
	pair, err := dkim2model.NewKeyPair(dkim2model.AlgorithmEd25519SHA256, privateDER, publicDER)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	handle, err := dkim2model.NewHandle(generation, "handle")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := dkim2model.NewProfile(generation, "profile", "example.test", dkim2model.RecordStatusActive, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := dkim2model.NewCredential(generation, profile.ID(), "selector", pair.Algorithm(), pair.PublicSPKIDER(), handle.ID())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := dkim2model.NewPolicy(
		generation, "tenant", profile.SigningDomain(), dkim2model.ProfileUseOriginator, profile.ID(),
		dkim2model.RecordStatusActive, dkim2model.RolloutEnforce, dkim2model.CompatibilityStrict, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := dkim2model.NewKeyMaterial(generation, policy.TenantID(), profile.SigningDomain(), policy.Use(), handle.ID(), pair)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = material.Close() }()
	result, err := dkim2model.NewGenerationWithState(
		generation, state, []dkim2model.Handle{handle}, []dkim2model.Profile{profile},
		[]dkim2model.Credential{credential}, []dkim2model.Policy{policy}, []*dkim2model.KeyMaterial{material},
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
