package dkim2model

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type collisionSet struct {
	selectors map[string]bool
	handles   map[string]bool
}

func (c collisionSet) SelectorUsed(value string) (bool, error) { return c.selectors[value], nil }
func (c collisionSet) HandleUsed(value string) (bool, error)   { return c.handles[value], nil }

func TestPlanRotationReplacesWholeBindingAndPreservesUnrelatedRecords(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	original, err := current.Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()

	candidate, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, AllocationAttempts: 16,
		Random:  &sequenceReader{},
		History: collisionSet{selectors: map[string]bool{}, handles: map[string]bool{}},
		Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
			return GenerateKeyPair(algorithm, bits, nil)
		},
	})
	if err != nil {
		t.Fatalf("PlanRotation() error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	if !current.Equivalent(original) {
		t.Fatal("rotation mutated the input generation")
	}
	profile, found := candidate.ProfileByDomain("one.example")
	if !found || profile.ID() != "profile-one" || profile.Status() != RecordStatusActive {
		t.Fatalf("rotated profile facts changed: %#v", profile)
	}
	notBefore, notAfter, present := profile.ValidityWindow()
	if !present || !notBefore.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!notAfter.Equal(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("rotation changed the profile validity window")
	}
	policy := policyForModelDomain(candidate, "one.example")
	if policy.TenantID() != "tenant" || policy.Use() != ProfileUseOriginator ||
		policy.ProfileID() != "profile-one" || policy.Status() != RecordStatusActive ||
		policy.Rollout() != RolloutEnforce || policy.Compatibility() != CompatibilityStrict {
		t.Fatalf("rotation changed policy facts: %#v", policy)
	}
	credentials := credentialsForModelProfile(candidate, profile.ID())
	if len(credentials) != 2 || credentials[0].Algorithm() != AlgorithmRSASHA256 ||
		credentials[1].Algorithm() != AlgorithmEd25519SHA256 {
		t.Fatalf("algorithm set changed: %#v", credentials)
	}
	for _, credential := range credentials {
		if credential.Selector() == "selector-one-rsa" || credential.Selector() == "selector-one-ed" ||
			credential.HandleID() == "handle-one-rsa" || credential.HandleID() == "handle-one-ed" {
			t.Fatal("rotation reused a current selector or handle")
		}
	}
	if _, found := candidate.CredentialByDomainSelector("two.example", "selector-two-ed"); !found {
		t.Fatal("unrelated domain was not preserved")
	}
	if candidate.Number() != 2 || candidate.State() != DatasetStateStaging {
		t.Fatalf("candidate metadata = %d %q", candidate.Number(), candidate.State())
	}
}

func TestPlanGlobalRotationReplacesEveryDueBindingInOneSuccessor(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	history := lineageHistoryForGenerations(t, current)
	candidate, decisions, err := PlanGlobalRotation(GlobalRotationPlan{
		Current: current, NextGeneration: 2, Now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		History: history, Identifiers: collisionSet{}, Random: &sequenceReader{},
		Limits: RotationLimits{RotateAfter: 30 * 24 * time.Hour, MaximumClockSkew: 5 * time.Minute,
			AllocationAttempts: 16, RSABits: DefaultRSABits, MaximumBindings: 10},
		Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
			return GenerateKeyPair(algorithm, bits, nil)
		},
	})
	if err != nil {
		t.Fatalf("PlanGlobalRotation() error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	if len(decisions) != 2 {
		t.Fatalf("rotated bindings = %d, want 2", len(decisions))
	}
	for _, domain := range []string{"one.example", "two.example"} {
		profile, found := candidate.ProfileByDomain(domain)
		if !found {
			t.Fatalf("candidate missing %s", domain)
		}
		for _, credential := range credentialsForModelProfile(candidate, profile.ID()) {
			if _, found := current.CredentialByDomainSelector(domain, credential.Selector()); found {
				t.Fatalf("%s retained a due selector", domain)
			}
		}
	}
}

func TestPlanGlobalRotationPreservesEveryNonDueBinding(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	history := lineageHistoryForGenerations(t, current)
	// Make only the first binding old enough to rotate.
	for index := range history.Facts {
		if history.Facts[index].domain == "two.example" {
			history.Facts[index].created = "20260801000000Z"
		}
	}
	candidate, decisions, err := PlanGlobalRotation(GlobalRotationPlan{
		Current: current, NextGeneration: 2, Now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		History: history, Identifiers: collisionSet{}, Random: &sequenceReader{},
		Limits: RotationLimits{RotateAfter: 30 * 24 * time.Hour, MaximumClockSkew: 5 * time.Minute,
			AllocationAttempts: 16, RSABits: DefaultRSABits, MaximumBindings: 10},
		Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
			return GenerateKeyPair(algorithm, bits, nil)
		},
	})
	if err != nil {
		t.Fatalf("PlanGlobalRotation() error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	if len(decisions) != 1 || decisions[0].Domain() != "one.example" {
		t.Fatalf("decisions = %#v", decisions)
	}
	if _, found := candidate.CredentialByDomainSelector("two.example", "selector-two-ed"); !found {
		t.Fatal("non-due binding changed")
	}
}

func TestPlanRotationSucceedsForEachExactAlgorithmSet(t *testing.T) {
	for _, test := range []struct {
		name       string
		algorithms []Algorithm
	}{
		{name: "rsa only", algorithms: []Algorithm{AlgorithmRSASHA256}},
		{name: "ed25519 only", algorithms: []Algorithm{AlgorithmEd25519SHA256}},
		{name: "dual", algorithms: []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := activeBindingGeneration(t, 7, test.algorithms...)
			defer func() { _ = current.Close() }()
			original, err := current.Clone()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = original.Close() }()
			candidate, err := PlanRotation(RotationPlan{
				Current: current, NextGeneration: 8, TenantID: "tenant", Domain: "one.example",
				Use: ProfileUseOriginator, Algorithms: append([]Algorithm(nil), test.algorithms...),
				RSABits: DefaultRSABits, AllocationAttempts: 16, Random: &sequenceReader{}, History: collisionSet{},
				Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
					return GenerateKeyPair(algorithm, bits, nil)
				},
			})
			if err != nil {
				t.Fatalf("PlanRotation() error = %v", err)
			}
			defer func() { _ = candidate.Close() }()
			credentials := credentialsForModelProfile(candidate, "profile-one")
			if len(credentials) != len(test.algorithms) {
				t.Fatalf("credentials = %d", len(credentials))
			}
			for index, credential := range credentials {
				if credential.Algorithm() != test.algorithms[index] {
					t.Fatalf("algorithm[%d] = %q", index, credential.Algorithm())
				}
			}
			if !current.Equivalent(original) {
				t.Fatal("successful rotation mutated its input snapshot")
			}
		})
	}
}

func TestPlanRotationRejectsAlgorithmDowngradeBeforeRandomness(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	random := &countingReader{}
	candidate, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, Algorithms: []Algorithm{AlgorithmEd25519SHA256},
		RSABits: DefaultRSABits, AllocationAttempts: 16, Random: random, History: collisionSet{},
	})
	if err == nil || candidate != nil {
		t.Fatal("algorithm downgrade was accepted")
	}
	if random.reads != 0 {
		t.Fatalf("randomness read before algorithm-set validation: %d", random.reads)
	}
}

func TestPlanRotationRejectsProfileSharedByAnotherPolicyBeforeRandomness(t *testing.T) {
	current := activeBindingGeneration(t, 1, AlgorithmEd25519SHA256)
	defer func() { _ = current.Close() }()
	materials := current.KeyMaterials()
	defer closeKeyMaterials(materials)
	second, err := NewPolicy(
		1, "second-tenant", "one.example", ProfileUseOriginator, "profile-one",
		RecordStatusActive, RolloutEnforce, CompatibilityStrict, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := NewGeneration(
		1, current.Handles(), current.Profiles(), current.Credentials(),
		append(current.Policies(), second), materials,
	)
	if err != nil {
		t.Fatalf("shared-profile fixture must be structurally valid: %v", err)
	}
	defer func() { _ = shared.Close() }()
	random := &countingReader{}
	candidate, err := PlanRotation(RotationPlan{
		Current: shared, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, AllocationAttempts: 16, Random: random, History: collisionSet{},
	})
	if err == nil || candidate != nil {
		t.Fatal("rotation accepted a profile shared by another policy")
	}
	if random.reads != 0 {
		t.Fatalf("ambiguous profile ownership consumed randomness: %d", random.reads)
	}
}

func TestPlanRotationBoundsHistoricalCollisions(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	history := collisionSet{selectors: map[string]bool{}, handles: map[string]bool{}}
	for index := byte(0); index < 16; index++ {
		history.selectors["dkim2-"+strings.Repeat(fmt.Sprintf("%02x", index), 12)] = true
	}
	_, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, AllocationAttempts: 16,
		Random: &sequenceReader{}, History: history,
	})
	if err == nil {
		t.Fatal("bounded historical selector collisions were accepted")
	}
}

func TestPlanRotationBoundsHistoricalHandleCollisions(t *testing.T) {
	current := activeBindingGeneration(t, 1, AlgorithmEd25519SHA256)
	defer func() { _ = current.Close() }()
	history := collisionSet{selectors: map[string]bool{}, handles: map[string]bool{}}
	for index := byte(1); index <= 16; index++ {
		history.handles["key-"+strings.Repeat(fmt.Sprintf("%02x", index), 12)] = true
	}
	if candidate, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, AllocationAttempts: 16, Random: &sequenceReader{}, History: history,
	}); err == nil || candidate != nil {
		t.Fatal("bounded historical handle collisions were accepted")
	}
}

func TestPlanRotationRejectsGenerationOverflowBeforeRandomness(t *testing.T) {
	current := activeBindingGeneration(t, ^uint64(0), AlgorithmEd25519SHA256)
	defer func() { _ = current.Close() }()
	random := &countingReader{}
	if candidate, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 1, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, AllocationAttempts: 16, Random: random, History: collisionSet{},
	}); err == nil || candidate != nil {
		t.Fatal("generation overflow was accepted")
	}
	if random.reads != 0 {
		t.Fatalf("overflow consumed randomness: %d", random.reads)
	}
}

func TestPlanRotationClosesGeneratedOwnersWhenGeneratorFails(t *testing.T) {
	current := activeBindingGeneration(t, 1, AlgorithmRSASHA256, AlgorithmEd25519SHA256)
	defer func() { _ = current.Close() }()
	var generated []*KeyPair
	generate := func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
		pair, err := GenerateKeyPair(algorithm, bits, nil)
		if err != nil {
			return nil, err
		}
		generated = append(generated, pair)
		if len(generated) == 2 {
			return pair, errors.New("synthetic generation failure")
		}
		return pair, nil
	}
	if candidate, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, AllocationAttempts: 16, Random: &sequenceReader{},
		History: collisionSet{}, Generate: generate,
	}); err == nil || candidate != nil {
		t.Fatal("generator failure was accepted")
	}
	if len(generated) != 2 {
		t.Fatalf("generated owners = %d", len(generated))
	}
	for index, pair := range generated {
		if pair.Algorithm() != "" {
			t.Fatalf("generated owner %d remains open", index)
		}
	}
}

func TestEligibleBindingsUsesCanonicalLineageClock(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	var facts []LineageFact
	for _, credential := range current.Credentials() {
		profile, _ := current.ProfileByID(credential.ProfileID())
		fact, err := NewLineageFact(
			1, "20250701000000Z", "tenant", profile.SigningDomain(), ProfileUseOriginator,
			credential.Selector(), credential.Algorithm(), credential.PublicSPKIDER(), credential.HandleID(),
		)
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, fact)
	}
	limits := RotationLimits{RotateAfter: 365 * 24 * time.Hour, MaximumClockSkew: 300 * time.Second,
		AllocationAttempts: 16, RSABits: DefaultRSABits, MaximumBindings: 10}
	decisions, err := EligibleBindings(now, current, LineageHistory{Complete: true, Facts: facts}, limits)
	if err != nil {
		t.Fatalf("EligibleBindings() error = %v", err)
	}
	if len(decisions) != 2 || !decisions[0].Due() || decisions[0].Domain() != "one.example" {
		t.Fatalf("unexpected eligibility decisions: %v", decisions)
	}

	for _, history := range []LineageHistory{
		{Complete: false, Facts: facts},
		{Complete: true, Facts: append([]LineageFact(nil), facts[:len(facts)-1]...)},
	} {
		if _, err := EligibleBindings(now, current, history, limits); err == nil {
			t.Fatal("incomplete or ambiguous lineage was accepted")
		}
	}
	future := facts
	future[0].created = "20260802120501Z"
	if _, err := EligibleBindings(now, current, LineageHistory{Complete: true, Facts: future}, limits); err == nil {
		t.Fatal("future lineage beyond skew was accepted")
	}
}

func TestRotationTypesAreSecretSafeUnderFormatting(t *testing.T) {
	pair, err := GenerateEd25519KeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	public := pair.PublicSPKIDER()
	fact, err := NewLineageFact(1, "20250701000000Z", "tenant", "one.example", ProfileUseOriginator,
		"selector-secret", AlgorithmEd25519SHA256, public, "handle-secret")
	if err != nil {
		t.Fatalf("NewLineageFact() error = %v", err)
	}
	marker := fmt.Sprintf("%x", public)
	encoded, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{fmt.Sprintf("%v", fact), fmt.Sprintf("%+v", fact), fmt.Sprintf("%#v", fact), string(encoded)} {
		if output == "" || strings.Contains(output, "handle-secret") || strings.Contains(output, marker) {
			t.Fatalf("lineage formatting exposed protected facts: %q", output)
		}
	}
}

type countingReader struct{ reads int }

func (r *countingReader) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("unexpected random read")
}

type sequenceReader struct{ value byte }

func (r *sequenceReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = r.value
	}
	r.value++
	return len(buffer), nil
}

func activeRotationGeneration(t *testing.T) *Generation {
	t.Helper()
	builder, err := NewBuilder(1, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	add := func(domain, suffix string, algorithms ...Algorithm) {
		profile, err := NewProfile(1, "profile-"+suffix, domain, RecordStatusActive,
			time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		var credentials []Credential
		var materials []*KeyMaterial
		defer func() { closeKeyMaterials(materials) }()
		for _, algorithm := range algorithms {
			label := "ed"
			if algorithm == AlgorithmRSASHA256 {
				label = "rsa"
			}
			pair, err := GenerateKeyPair(algorithm, DefaultRSABits, nil)
			if err != nil {
				t.Fatal(err)
			}
			handle := "handle-" + suffix + "-" + label
			credential, credentialErr := NewCredential(1, profile.ID(), "selector-"+suffix+"-"+label, algorithm, pair.PublicSPKIDER(), handle)
			material, materialErr := NewKeyMaterial(1, "tenant", domain, ProfileUseOriginator, handle, pair)
			_ = pair.Close()
			if credentialErr != nil || materialErr != nil {
				t.Fatal(errors.Join(credentialErr, materialErr))
			}
			credentials = append(credentials, credential)
			materials = append(materials, material)
		}
		policy, err := NewPolicy(1, "tenant", domain, ProfileUseOriginator, profile.ID(), RecordStatusActive, RolloutEnforce, CompatibilityStrict, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := builder.AddProfileWithKeys(profile, credentials, policy, materials); err != nil {
			t.Fatal(err)
		}
	}
	add("one.example", "one", AlgorithmRSASHA256, AlgorithmEd25519SHA256)
	add("two.example", "two", AlgorithmEd25519SHA256)
	generation, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func activeBindingGeneration(t *testing.T, generation uint64, algorithms ...Algorithm) *Generation {
	t.Helper()
	builder, err := NewBuilder(generation, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	profile, err := NewProfile(generation, "profile-one", "one.example", RecordStatusActive,
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var credentials []Credential
	var materials []*KeyMaterial
	defer func() { closeKeyMaterials(materials) }()
	for _, algorithm := range algorithms {
		label := "ed"
		if algorithm == AlgorithmRSASHA256 {
			label = "rsa"
		}
		pair, err := GenerateKeyPair(algorithm, DefaultRSABits, nil)
		if err != nil {
			t.Fatal(err)
		}
		handle := "handle-one-" + label
		credential, credentialErr := NewCredential(generation, profile.ID(), "selector-one-"+label, algorithm, pair.PublicSPKIDER(), handle)
		material, materialErr := NewKeyMaterial(generation, "tenant", "one.example", ProfileUseOriginator, handle, pair)
		_ = pair.Close()
		if credentialErr != nil || materialErr != nil {
			t.Fatal(errors.Join(credentialErr, materialErr))
		}
		credentials = append(credentials, credential)
		materials = append(materials, material)
	}
	policy, err := NewPolicy(generation, "tenant", "one.example", ProfileUseOriginator, profile.ID(), RecordStatusActive, RolloutEnforce, CompatibilityStrict, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.AddProfileWithKeys(profile, credentials, policy, materials); err != nil {
		t.Fatal(err)
	}
	result, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func credentialsForModelProfile(generation *Generation, profileID string) []Credential {
	var result []Credential
	for _, credential := range generation.Credentials() {
		if credential.ProfileID() == profileID {
			result = append(result, credential)
		}
	}
	return result
}

func policyForModelDomain(generation *Generation, domain string) Policy {
	for _, policy := range generation.Policies() {
		if policy.SigningDomain() == domain {
			return policy
		}
	}
	return Policy{}
}
