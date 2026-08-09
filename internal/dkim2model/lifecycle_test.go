package dkim2model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPlanRetirementAcceptsExactlyOneCardinalityNeutralRotation(t *testing.T) {
	for _, test := range []struct {
		name       string
		algorithms []Algorithm
	}{
		{name: "rsa", algorithms: []Algorithm{AlgorithmRSASHA256}},
		{name: "ed25519", algorithms: []Algorithm{AlgorithmEd25519SHA256}},
		{name: "dual", algorithms: []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}},
	} {
		t.Run(test.name, func(t *testing.T) {
			predecessor := activeBindingGeneration(t, 1, test.algorithms...)
			defer func() { _ = predecessor.Close() }()
			current := rotatedCommittedGeneration(t, predecessor, 2, "tenant", "one.example", ProfileUseOriginator)
			defer func() { _ = current.Close() }()

			transition, err := PlanRetirement(current, predecessor)
			if err != nil {
				t.Fatalf("PlanRetirement() error = %v", err)
			}
			defer func() { _ = transition.Close() }()
			if transition.Intent() != TransitionIntentRetirement ||
				transition.PredecessorGeneration() != 1 || transition.CurrentGeneration() != 2 {
				t.Fatalf("unexpected transition metadata: %v", transition)
			}
			binding := transition.Binding()
			if binding.TenantID() != "tenant" || binding.Domain() != "one.example" ||
				binding.Use() != ProfileUseOriginator {
				t.Fatalf("unexpected binding: %v", binding)
			}
			oldCredentials := transition.RetiringCredentials()
			newCredentials := transition.ActiveCredentials()
			if len(oldCredentials) != len(test.algorithms) || len(newCredentials) != len(test.algorithms) {
				t.Fatalf("credential cardinality changed: %d -> %d", len(oldCredentials), len(newCredentials))
			}
			for index, algorithm := range test.algorithms {
				if oldCredentials[index].Algorithm() != algorithm || newCredentials[index].Algorithm() != algorithm ||
					oldCredentials[index].Selector() == newCredentials[index].Selector() ||
					bytes.Equal(oldCredentials[index].PublicSPKIDER(), newCredentials[index].PublicSPKIDER()) {
					t.Fatalf("credential %d was not completely replaced", index)
				}
			}
			oldPublic := oldCredentials[0].PublicSPKIDER()
			clear(oldPublic)
			if len(transition.RetiringCredentials()[0].PublicSPKIDER()) == 0 {
				t.Fatal("retirement credential accessor did not detach public bytes")
			}
		})
	}
}

func TestPlanRetirementRejectsMalformedOrAmbiguousDiffs(t *testing.T) {
	predecessor := activeRotationGeneration(t)
	defer func() { _ = predecessor.Close() }()
	rotated := rotatedCommittedGeneration(t, predecessor, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = rotated.Close() }()
	unchanged := rebasedGeneration(t, predecessor, 2, DatasetStateCommitted)
	defer func() { _ = unchanged.Close() }()
	staging := rebasedGeneration(t, predecessor, 2, DatasetStateStaging)
	defer func() { _ = staging.Close() }()
	twoChanges := replaceProfilesForTest(t, predecessor, 2, []string{"profile-one", "profile-two"})
	defer func() { _ = twoChanges.Close() }()
	partialDual := partialDualReplacementForTest(t, predecessor, 2)
	defer func() { _ = partialDual.Close() }()
	nonImmediate := rebasedGeneration(t, rotated, 3, DatasetStateCommitted)
	defer func() { _ = nonImmediate.Close() }()

	for _, test := range []struct {
		name        string
		current     *Generation
		predecessor *Generation
	}{
		{name: "nil current", current: nil, predecessor: predecessor},
		{name: "nil predecessor", current: rotated, predecessor: nil},
		{name: "unchanged", current: unchanged, predecessor: predecessor},
		{name: "staging", current: staging, predecessor: predecessor},
		{name: "multiple binding diff", current: twoChanges, predecessor: predecessor},
		{name: "partial dual diff", current: partialDual, predecessor: predecessor},
		{name: "non immediate", current: nonImmediate, predecessor: predecessor},
	} {
		t.Run(test.name, func(t *testing.T) {
			transition, err := PlanRetirement(test.current, test.predecessor)
			if err == nil || transition != nil {
				t.Fatalf("malformed retirement diff was accepted: %v", transition)
			}
		})
	}
}

func TestValidateRetirementEvidenceUsesOnlyInjectedExactFacts(t *testing.T) {
	activated := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	all := RetirementAttestations{
		RuntimeReload: true, RepeatedReadiness: true, Queues: true, EmittedSignatures: true,
		ExternalVerify: true, Backup: true, RollbackAuthority: true,
	}
	valid := RetirementEvidence{
		CurrentGeneration: 2, ActivatedAt: activated, ObservedAt: activated.Add(7 * 24 * time.Hour),
		MinimumOverlap: 7 * 24 * time.Hour, Attestations: all,
	}
	if err := ValidateRetirementEvidence(2, valid); err != nil {
		t.Fatalf("valid retirement evidence rejected: %v", err)
	}
	for _, mutate := range []func(*RetirementEvidence){
		func(value *RetirementEvidence) { value.CurrentGeneration = 3 },
		func(value *RetirementEvidence) { value.ActivatedAt = time.Time{} },
		func(value *RetirementEvidence) { value.ObservedAt = value.ActivatedAt.Add(-time.Second) },
		func(value *RetirementEvidence) { value.MinimumOverlap = 0 },
		func(value *RetirementEvidence) {
			value.ObservedAt = value.ActivatedAt.Add(value.MinimumOverlap - time.Second)
		},
		func(value *RetirementEvidence) { value.Attestations.Backup = false },
	} {
		candidate := valid
		mutate(&candidate)
		if err := ValidateRetirementEvidence(2, candidate); err == nil {
			t.Fatal("invalid retirement evidence was accepted")
		}
	}
}

func TestPlanForwardRollbackRebasesExactSourceBindingAndPreservesCurrentOthers(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	current := rotatedCommittedGeneration(t, source, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = current.Close() }()
	currentOriginal, err := current.Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = currentOriginal.Close() }()
	sourceOriginal, err := source.Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sourceOriginal.Close() }()

	transition, err := PlanForwardRollback(ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: 3,
		TenantID: "tenant", Domain: "one.example", Use: ProfileUseOriginator,
	})
	if err != nil {
		t.Fatalf("PlanForwardRollback() error = %v", err)
	}
	defer func() { _ = transition.Close() }()
	if transition.Intent() != TransitionIntentForwardRollback || transition.ExpectedCurrent() != 2 ||
		transition.SourceGeneration() != 1 || transition.CandidateNumber() != 3 {
		t.Fatalf("unexpected forward rollback metadata: %v", transition)
	}
	candidate, err := transition.Generation()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = candidate.Close() }()
	if candidate.Number() != 3 || candidate.State() != DatasetStateStaging {
		t.Fatalf("candidate metadata = %d %q", candidate.Number(), candidate.State())
	}
	assertBindingLogicallyEqual(t, candidate, source, "tenant", "one.example", ProfileUseOriginator)
	assertBindingLogicallyEqual(t, candidate, current, "tenant", "two.example", ProfileUseOriginator)
	if !current.Equivalent(currentOriginal) || !source.Equivalent(sourceOriginal) {
		t.Fatal("forward rollback mutated an input generation")
	}

	materials := source.KeyMaterials()
	defer closeKeyMaterials(materials)
	candidateMaterials := candidate.KeyMaterials()
	defer closeKeyMaterials(candidateMaterials)
	for _, sourceMaterial := range materials {
		if sourceMaterial.SigningDomain() != "one.example" {
			continue
		}
		candidateMaterial := materialForAlgorithm(candidateMaterials, "one.example", sourceMaterial.Algorithm())
		if candidateMaterial == nil {
			t.Fatal("rebased protected material is missing")
		}
		left := sourceMaterial.PrivatePKCS8DER()
		right := candidateMaterial.PrivatePKCS8DER()
		if !bytes.Equal(left, right) {
			t.Fatal("forward rollback did not preserve protected source material")
		}
		clear(left)
		clear(right)
	}
}

func TestPlanForwardRollbackRejectsMalformedNoopAndCollision(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	current := rotatedCommittedGeneration(t, source, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = current.Close() }()
	noOpCurrent := rotatedCommittedGeneration(t, source, 2, "tenant", "two.example", ProfileUseOriginator)
	defer func() { _ = noOpCurrent.Close() }()
	stagingSource := rebasedGeneration(t, source, 1, DatasetStateStaging)
	defer func() { _ = stagingSource.Close() }()
	collisionCurrent := rollbackCollisionGeneration(t, source, current)
	defer func() { _ = collisionCurrent.Close() }()

	valid := ForwardRollbackPlan{Current: current, Source: source, NextGeneration: 3,
		TenantID: "tenant", Domain: "one.example", Use: ProfileUseOriginator}
	for _, mutate := range []func(*ForwardRollbackPlan){
		func(value *ForwardRollbackPlan) { value.NextGeneration = 2 },
		func(value *ForwardRollbackPlan) { value.Source = value.Current },
		func(value *ForwardRollbackPlan) { value.Source = stagingSource },
		func(value *ForwardRollbackPlan) { value.Current = noOpCurrent },
		func(value *ForwardRollbackPlan) { value.Current = collisionCurrent; value.NextGeneration = 4 },
		func(value *ForwardRollbackPlan) { value.Domain = "ONE.example" },
	} {
		plan := valid
		mutate(&plan)
		transition, err := PlanForwardRollback(plan)
		if err == nil || transition != nil {
			t.Fatalf("invalid forward rollback was accepted: %v", transition)
		}
	}
}

func TestValidateRotationCandidateIntentAcceptsOnlyFreshNormalRotation(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	candidate := rotatedStagingGeneration(t, current, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = candidate.Close() }()
	history := lineageHistoryForGenerations(t, current, candidate)

	binding, err := ValidateRotationCandidateIntent(current, candidate, history)
	if err != nil {
		t.Fatalf("ValidateRotationCandidateIntent() error = %v", err)
	}
	if binding.TenantID() != "tenant" || binding.Domain() != "one.example" ||
		binding.Use() != ProfileUseOriginator {
		t.Fatalf("unexpected rotation binding: %v", binding)
	}

	committed := rebasedGeneration(t, candidate, candidate.Number(), DatasetStateCommitted)
	defer func() { _ = committed.Close() }()
	if _, err := ValidateRotationCandidateIntent(current, committed, history); err != nil {
		t.Fatalf("committed-unreachable normal rotation rejected: %v", err)
	}
	if _, err := ValidateRotationCandidateIntent(current, candidate, LineageHistory{Complete: false, Facts: history.Facts}); err == nil {
		t.Fatal("incomplete rotation lineage was accepted")
	}
	if _, err := ValidateRotationCandidateIntent(current, candidate, LineageHistory{Complete: true}); err == nil {
		t.Fatal("empty complete rotation lineage was accepted")
	}
}

func TestValidateRotationCandidateIntentRejectsForwardRollbackLineage(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	current := rotatedCommittedGeneration(t, source, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = current.Close() }()
	rollback, err := PlanForwardRollback(ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: 3,
		TenantID: "tenant", Domain: "one.example", Use: ProfileUseOriginator,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rollback.Close() }()
	candidate, err := rollback.Generation()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = candidate.Close() }()
	history := lineageHistoryForGenerations(t, source, current, candidate)
	if binding, err := ValidateRotationCandidateIntent(current, candidate, history); err == nil {
		t.Fatalf("forward rollback was accepted as automatic rotation: %v", binding)
	}
}

func TestValidateRotationCandidateIntentRejectsAnyHistoricalTargetReuse(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	candidate := rotatedStagingGeneration(t, current, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = candidate.Close() }()
	base := lineageHistoryForGenerations(t, current, candidate)
	policy, profile, credentials, err := exactActiveBinding(candidate, "tenant", "one.example", ProfileUseOriginator)
	if err != nil || len(credentials) == 0 {
		t.Fatal("candidate fixture binding missing")
	}
	target := credentials[0]
	prior := func(selector, handle string, public []byte) LineageFact {
		t.Helper()
		fact, factErr := NewLineageFact(
			1, "20250101000000Z", policy.TenantID(), profile.SigningDomain(), policy.Use(),
			selector, target.Algorithm(), public, handle,
		)
		if factErr != nil {
			t.Fatal(factErr)
		}
		return fact
	}
	for _, test := range []struct {
		name string
		fact LineageFact
	}{
		{name: "selector", fact: prior(target.Selector(), "historical-handle", current.Credentials()[0].PublicSPKIDER())},
		{name: "handle", fact: prior("historical-selector.example", target.HandleID(), current.Credentials()[0].PublicSPKIDER())},
		{name: "public key", fact: prior("historical-selector.example", "historical-handle", target.PublicSPKIDER())},
	} {
		t.Run(test.name, func(t *testing.T) {
			history := LineageHistory{Complete: true, Facts: append(append([]LineageFact(nil), base.Facts...), test.fact)}
			if binding, err := ValidateRotationCandidateIntent(current, candidate, history); err == nil {
				t.Fatalf("historical %s reuse was accepted: %v", test.name, binding)
			}
		})
	}
}

func TestValidateRotationCandidateIntentRejectsMalformedDiffAndLineageShape(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()
	candidate := rotatedStagingGeneration(t, current, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = candidate.Close() }()
	history := lineageHistoryForGenerations(t, current, candidate)
	unchanged := rebasedGeneration(t, current, 2, DatasetStateStaging)
	defer func() { _ = unchanged.Close() }()
	multiple := replaceProfilesForTest(t, current, 2, []string{"profile-one", "profile-two"})
	defer func() { _ = multiple.Close() }()

	for _, malformed := range []*Generation{nil, unchanged, multiple} {
		if binding, err := ValidateRotationCandidateIntent(current, malformed, history); err == nil {
			t.Fatalf("malformed candidate intent was accepted: %v", binding)
		}
	}
	missingCurrent := history
	missingCurrent.Facts = append([]LineageFact(nil), history.Facts[1:]...)
	if binding, err := ValidateRotationCandidateIntent(current, candidate, missingCurrent); err == nil {
		t.Fatalf("history missing a current lineage was accepted: %v", binding)
	}
	missingCandidate := LineageHistory{Complete: true, Facts: append([]LineageFact(nil), history.Facts...)}
	missingCandidate.Facts = missingCandidate.Facts[:len(missingCandidate.Facts)-1]
	if binding, err := ValidateRotationCandidateIntent(current, candidate, missingCandidate); err == nil {
		t.Fatalf("history missing a candidate lineage was accepted: %v", binding)
	}
	futureFact := history.Facts[0]
	futureFact.generation = candidate.Number() + 1
	withFuture := LineageHistory{Complete: true, Facts: append(append([]LineageFact(nil), history.Facts...), futureFact)}
	if binding, err := ValidateRotationCandidateIntent(current, candidate, withFuture); err == nil {
		t.Fatalf("history containing a higher generation was accepted: %v", binding)
	}
	extraCredential := current.Credentials()[0]
	extraCurrent, err := NewLineageFact(
		current.Number(), "20250101000000Z", "extra-tenant", "extra.example", ProfileUseOriginator,
		"extra-selector", extraCredential.Algorithm(), extraCredential.PublicSPKIDER(), "extra-handle",
	)
	if err != nil {
		t.Fatal(err)
	}
	withExtraCurrent := LineageHistory{Complete: true, Facts: append(append([]LineageFact(nil), history.Facts...), extraCurrent)}
	if binding, err := ValidateRotationCandidateIntent(current, candidate, withExtraCurrent); err == nil {
		t.Fatalf("extra current-generation lineage was accepted: %v", binding)
	}
	extraCandidate := extraCurrent
	extraCandidate.generation = candidate.Number()
	withExtraCandidate := LineageHistory{Complete: true, Facts: append(append([]LineageFact(nil), history.Facts...), extraCandidate)}
	if binding, err := ValidateRotationCandidateIntent(current, candidate, withExtraCandidate); err == nil {
		t.Fatalf("extra candidate-generation lineage was accepted: %v", binding)
	}
}

func TestLifecycleTypesUseClosedVocabulariesAndProtectedFormatting(t *testing.T) {
	credential, err := NewObservationCredential("selector.example", AlgorithmEd25519SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewObservationCredential("Selector.example", AlgorithmEd25519SHA256); err == nil {
		t.Fatal("noncanonical observation selector was accepted")
	}
	if _, err := NewObservationCredential("selector.example", Algorithm("unknown")); err == nil {
		t.Fatal("unknown observation algorithm was accepted")
	}
	for phase := LifecyclePhaseIdle; phase <= LifecyclePhaseRetired; phase++ {
		observation, err := NewLifecycleObservation(7, phase, "one.example", []ObservationCredential{credential})
		if err != nil || observation.Phase() != phase || phase.Name() == "" || len(observation.Credentials()) != 1 {
			t.Fatalf("phase %d rejected: %v", phase, err)
		}
	}
	if _, err := NewLifecycleObservation(7, LifecyclePhase(255), "one.example", nil); err == nil {
		t.Fatal("unknown lifecycle phase was accepted")
	}
	if _, err := NewLifecycleObservation(7, LifecyclePhaseActivated, "one.example", []ObservationCredential{credential, credential}); err == nil {
		t.Fatal("duplicate observation credential was accepted")
	}
	if TransitionIntent(255).Known() || LifecyclePhase(255).Known() {
		t.Fatal("unknown closed vocabulary value was accepted")
	}

	predecessor := activeBindingGeneration(t, 1, AlgorithmEd25519SHA256)
	defer func() { _ = predecessor.Close() }()
	current := rotatedCommittedGeneration(t, predecessor, 2, "tenant", "one.example", ProfileUseOriginator)
	defer func() { _ = current.Close() }()
	retirement, err := PlanRetirement(current, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retirement.Close() }()
	rollback, err := PlanForwardRollback(ForwardRollbackPlan{Current: current, Source: predecessor, NextGeneration: 3,
		TenantID: "tenant", Domain: "one.example", Use: ProfileUseOriginator})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rollback.Close() }()
	oldCredential := retirement.RetiringCredentials()[0]
	publicMarker := fmt.Sprintf("%x", oldCredential.PublicSPKIDER())
	privateMarker := "handle-one-ed"
	evidence := RetirementEvidence{CurrentGeneration: 2, ActivatedAt: time.Now().UTC(), ObservedAt: time.Now().UTC(), MinimumOverlap: time.Hour}
	objects := []any{retirement, rollback, retirement.Binding(), oldCredential, evidence}
	for _, object := range objects {
		encoded, marshalErr := json.Marshal(object)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		for _, output := range []string{fmt.Sprintf("%v", object), fmt.Sprintf("%+v", object), fmt.Sprintf("%#v", object), string(encoded)} {
			if strings.Contains(output, privateMarker) || strings.Contains(output, publicMarker) || strings.Contains(output, "one.example") {
				t.Fatalf("lifecycle formatting exposed protected facts: %q", output)
			}
		}
	}
	if err := rollback.Close(); err != nil {
		t.Fatal(err)
	}
	if rollback.Intent() != 0 || rollback.CandidateNumber() != 0 {
		t.Fatal("closed rollback transition remained valid")
	}
	if candidate, err := rollback.Generation(); err == nil || candidate != nil {
		t.Fatal("closed rollback transition returned a candidate")
	}
}

func rotatedCommittedGeneration(t *testing.T, predecessor *Generation, number uint64, tenant, domain string, use ProfileUse) *Generation {
	t.Helper()
	staging := rotatedStagingGeneration(t, predecessor, number, tenant, domain, use)
	defer func() { _ = staging.Close() }()
	materials := staging.KeyMaterials()
	defer closeKeyMaterials(materials)
	result, err := NewGeneration(number, staging.Handles(), staging.Profiles(), staging.Credentials(), staging.Policies(), materials)
	if err != nil {
		t.Fatalf("commit fixture error = %v", err)
	}
	return result
}

func rotatedStagingGeneration(t *testing.T, predecessor *Generation, number uint64, tenant, domain string, use ProfileUse) *Generation {
	t.Helper()
	staging, err := PlanRotation(RotationPlan{
		Current: predecessor, NextGeneration: number, TenantID: tenant, Domain: domain, Use: use,
		RSABits: DefaultRSABits, AllocationAttempts: 16, Random: &sequenceReader{}, History: collisionSet{},
	})
	if err != nil {
		t.Fatalf("PlanRotation() fixture error = %v", err)
	}
	return staging
}

func lineageHistoryForGenerations(t *testing.T, generations ...*Generation) LineageHistory {
	t.Helper()
	history := LineageHistory{Complete: true}
	for _, generation := range generations {
		for _, credential := range generation.Credentials() {
			profile, found := generation.ProfileByID(credential.ProfileID())
			policy, policyFound := exclusivePolicyForProfile(generation, credential.ProfileID())
			if !found || !policyFound {
				t.Fatal("lineage fixture binding is ambiguous")
			}
			created := fmt.Sprintf("2025%02d01000000Z", generation.Number())
			fact, err := NewLineageFact(
				generation.Number(), created, policy.TenantID(), profile.SigningDomain(), policy.Use(),
				credential.Selector(), credential.Algorithm(), credential.PublicSPKIDER(), credential.HandleID(),
			)
			if err != nil {
				t.Fatal(err)
			}
			history.Facts = append(history.Facts, fact)
		}
	}
	return history
}

func rebasedGeneration(t *testing.T, source *Generation, number uint64, state DatasetState) *Generation {
	t.Helper()
	if source.Number() == number {
		materials := source.KeyMaterials()
		defer closeKeyMaterials(materials)
		result, err := NewGenerationWithState(number, state, source.Handles(), source.Profiles(), source.Credentials(), source.Policies(), materials)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	builder, err := source.NextBuilder(number, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	result, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func replaceProfilesForTest(t *testing.T, predecessor *Generation, number uint64, profileIDs []string) *Generation {
	t.Helper()
	builder, err := predecessor.NextBuilder(number, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	for profileIndex, profileID := range profileIDs {
		profile, found := predecessor.ProfileByID(profileID)
		if !found {
			t.Fatal("fixture profile missing")
		}
		old := credentialsForModelProfile(predecessor, profileID)
		credentials := make([]Credential, 0, len(old))
		materials := make([]*KeyMaterial, 0, len(old))
		for index, credential := range old {
			pair, pairErr := GenerateKeyPair(credential.Algorithm(), DefaultRSABits, nil)
			if pairErr != nil {
				t.Fatal(pairErr)
			}
			handle := fmt.Sprintf("replacement-%d-%d", profileIndex, index)
			selector := fmt.Sprintf("replacement-%d-%d", profileIndex, index)
			newCredential, credentialErr := NewCredential(number, profileID, selector, credential.Algorithm(), pair.PublicSPKIDER(), handle)
			policy, policyFound := exclusivePolicyForProfile(predecessor, profileID)
			if !policyFound {
				t.Fatal("fixture policy missing")
			}
			material, materialErr := NewKeyMaterial(number, policy.TenantID(), profile.SigningDomain(), policy.Use(), handle, pair)
			_ = pair.Close()
			if credentialErr != nil || materialErr != nil {
				t.Fatal(ErrInvalid)
			}
			credentials = append(credentials, newCredential)
			materials = append(materials, material)
		}
		if err := builder.ReplaceProfileKeys(profileID, credentials, materials); err != nil {
			closeKeyMaterials(materials)
			t.Fatal(err)
		}
		closeKeyMaterials(materials)
	}
	result, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func partialDualReplacementForTest(t *testing.T, predecessor *Generation, number uint64) *Generation {
	t.Helper()
	builder, err := predecessor.NextBuilder(number, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	oldCredentials := credentialsForModelProfile(predecessor, "profile-one")
	credentials := make([]Credential, 0, len(oldCredentials))
	materials := make([]*KeyMaterial, 0, len(oldCredentials))
	defer closeKeyMaterials(materials)
	for _, old := range oldCredentials {
		if old.Algorithm() == AlgorithmEd25519SHA256 {
			credentials = append(credentials, rebaseCredential(old, number))
			material, _ := materialByHandle(predecessor, old.HandleID())
			rebased, rebaseErr := rebaseKeyMaterial(material, number)
			if rebaseErr != nil {
				t.Fatal(rebaseErr)
			}
			materials = append(materials, rebased)
			continue
		}
		pair, pairErr := GenerateKeyPair(old.Algorithm(), DefaultRSABits, nil)
		if pairErr != nil {
			t.Fatal(pairErr)
		}
		credential, credentialErr := NewCredential(number, "profile-one", "partial-rsa", old.Algorithm(), pair.PublicSPKIDER(), "partial-rsa-handle")
		material, materialErr := NewKeyMaterial(number, "tenant", "one.example", ProfileUseOriginator, "partial-rsa-handle", pair)
		_ = pair.Close()
		if credentialErr != nil || materialErr != nil {
			t.Fatal(ErrInvalid)
		}
		credentials = append(credentials, credential)
		materials = append(materials, material)
	}
	if err := builder.ReplaceProfileKeys("profile-one", credentials, materials); err != nil {
		t.Fatal(err)
	}
	result, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func rollbackCollisionGeneration(t *testing.T, source, current *Generation) *Generation {
	t.Helper()
	builder, err := current.NextBuilder(3, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	sourceCredential, found := source.CredentialByDomainSelector("one.example", "selector-one-ed")
	if !found {
		t.Fatal("source selector fixture missing")
	}
	pair, err := GenerateEd25519KeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	credential, credentialErr := NewCredential(3, "profile-two", sourceCredential.Selector(), AlgorithmEd25519SHA256, pair.PublicSPKIDER(), "collision-handle")
	material, materialErr := NewKeyMaterial(3, "tenant", "two.example", ProfileUseOriginator, "collision-handle", pair)
	if credentialErr != nil || materialErr != nil {
		t.Fatal(ErrInvalid)
	}
	defer func() { _ = material.Close() }()
	if err := builder.ReplaceProfileKeys("profile-two", []Credential{credential}, []*KeyMaterial{material}); err != nil {
		t.Fatal(err)
	}
	result, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertBindingLogicallyEqual(t *testing.T, left, right *Generation, tenant, domain string, use ProfileUse) {
	t.Helper()
	leftPolicy, leftProfile, leftCredentials, err := exactActiveBinding(left, tenant, domain, use)
	if err != nil {
		t.Fatal(err)
	}
	rightPolicy, rightProfile, rightCredentials, err := exactActiveBinding(right, tenant, domain, use)
	if err != nil {
		t.Fatal(err)
	}
	if !bindingsEqual(left, leftPolicy, leftProfile, leftCredentials, right, rightPolicy, rightProfile, rightCredentials) {
		t.Fatalf("binding %s was not preserved", domain)
	}
}

func materialForAlgorithm(materials []*KeyMaterial, domain string, algorithm Algorithm) *KeyMaterial {
	for _, material := range materials {
		if material.SigningDomain() == domain && material.Algorithm() == algorithm {
			return material
		}
	}
	return nil
}
