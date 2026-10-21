package dkim2model

import (
	"fmt"
	"testing"
	"time"
)

// createModelFixture builds a complete inactive addition with native key custody and independent lineage evidence.
func createModelFixture(t *testing.T, use ProfileUse, algorithms []Algorithm) (*Generation, *Generation, LineageHistory, CreateCandidateIntent) {
	t.Helper()
	source := activeBindingGeneration(t, 2, AlgorithmEd25519SHA256)
	t.Cleanup(func() { _ = source.Close() })
	builder, err := source.NextBuilder(3, DatasetStateStaging)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	profile, err := NewProfile(3, "profile-new", "new.example", RecordStatusDisabled, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var credentials []Credential
	var materials []*KeyMaterial
	defer func() { closeKeyMaterials(materials) }()
	for index, algorithm := range algorithms {
		pair, err := GenerateKeyPair(algorithm, DefaultRSABits, nil)
		if err != nil {
			t.Fatal(err)
		}
		handle, selector := fmt.Sprintf("handle-new-%d", index), fmt.Sprintf("selector-new-%d", index)
		credential, credentialErr := NewCredential(3, profile.ID(), selector, algorithm, pair.PublicSPKIDER(), handle)
		material, materialErr := NewKeyMaterial(3, "tenant", "new.example", use, handle, pair)
		_ = pair.Close()
		if credentialErr != nil || materialErr != nil {
			t.Fatal("invalid fixture key owner")
		}
		credentials = append(credentials, credential)
		materials = append(materials, material)
	}
	policy, err := NewPolicy(3, "tenant", "new.example", use, profile.ID(), RecordStatusDisabled, RolloutOff, CompatibilityStrict, "feedback-one")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.AddProfileWithKeys(profile, credentials, policy, materials); err != nil {
		t.Fatal(err)
	}
	candidate, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = candidate.Close() })
	intent := CreateCandidateIntent{TenantID: "tenant", Domains: []string{"new.example"}, Use: use,
		Algorithms: algorithms, RSABits: DefaultRSABits, FeedbackRouteID: "feedback-one", MaximumBindings: 4}
	return source, candidate, lineageHistoryForGenerations(t, source, candidate), intent
}

// TestValidateCreateCandidateIntentAlgorithmAndUseMatrix covers every existing native custody use and exact algorithm set.
func TestValidateCreateCandidateIntentAlgorithmAndUseMatrix(t *testing.T) {
	for _, use := range []ProfileUse{ProfileUseOriginator, ProfileUseOrdinaryTransit, ProfileUseDeliveryStatus} {
		for _, algorithms := range [][]Algorithm{{AlgorithmEd25519SHA256}, {AlgorithmRSASHA256}, {AlgorithmRSASHA256, AlgorithmEd25519SHA256}} {
			t.Run(string(use)+"/"+fmt.Sprint(len(algorithms))+"/"+string(algorithms[0]), func(t *testing.T) {
				source, candidate, history, intent := createModelFixture(t, use, algorithms)
				for index := range algorithms {
					intent.Selectors = append(intent.Selectors, fmt.Sprintf("selector-new-%d", index))
				}
				bindings, err := ValidateCreateCandidateIntent(source, candidate, history, intent)
				if err != nil || len(bindings) != 1 || bindings[0].Use() != use || bindings[0].Domain() != "new.example" || bindings[0].TenantID() != "tenant" {
					t.Fatal("complete inactive candidate rejected", err)
				}
				intent.Selectors[0] = "different-selector"
				if _, err := ValidateCreateCandidateIntent(source, candidate, history, intent); err == nil {
					t.Fatal("different explicit selector accepted")
				}
				intent.Selectors = nil
				if algorithms[0] == AlgorithmRSASHA256 {
					intent.RSABits = 4096
					if _, err := ValidateCreateCandidateIntent(source, candidate, history, intent); err == nil {
						t.Fatal("different RSA size accepted")
					}
				}
			})
		}
	}
}

// TestValidateCreateCandidateIntentLineageRejects rejects incomplete projections and all forms of prior key identity reuse.
func TestValidateCreateCandidateIntentLineageRejects(t *testing.T) {
	for _, name := range []string{"incomplete", "missing", "duplicate", "future", "old-selector", "old-handle", "old-key"} {
		t.Run(name, func(t *testing.T) {
			source, candidate, history, intent := createModelFixture(t, ProfileUseOrdinaryTransit, []Algorithm{AlgorithmEd25519SHA256})
			switch name {
			case "incomplete":
				history.Complete = false
			case "missing":
				history.Facts = history.Facts[:len(history.Facts)-1]
			case "duplicate":
				history.Facts = append(history.Facts, history.Facts[len(history.Facts)-1])
			default:
				credential := credentialsForProfile(candidate, "profile-new")[0]
				public := source.Credentials()[0].PublicSPKIDER()
				selector, handle, generation := "older-selector", "older-handle", uint64(1)
				switch name {
				case "future":
					generation = 4
				case "old-selector":
					selector = credential.Selector()
				case "old-handle":
					handle = credential.HandleID()
				case "old-key":
					public = credential.PublicSPKIDER()
				}
				fact, err := NewLineageFact(generation, "20250101000000Z", "tenant", "historical.example", ProfileUseOriginator, selector, credential.Algorithm(), public, handle)
				if err != nil {
					t.Fatal(err)
				}
				history.Facts = append(history.Facts, fact)
			}
			if _, err := ValidateCreateCandidateIntent(source, candidate, history, intent); err == nil {
				t.Fatal("incomplete or reused lineage accepted")
			}
		})
	}
}

// TestValidateCreateCandidateIntentRejectsHiddenChanges checks unrequested record removal, addition, and malformed request scope.
func TestValidateCreateCandidateIntentRejectsHiddenChanges(t *testing.T) {
	for _, name := range []string{"nil-source", "nil-candidate", "old-profile-removed", "extra-policy", "invalid-use", "empty-domain", "unknown-algorithm", "duplicate-algorithm", "noncanonical-selector"} {
		t.Run(name, func(t *testing.T) {
			source, candidate, history, intent := createModelFixture(t, ProfileUseOrdinaryTransit, []Algorithm{AlgorithmEd25519SHA256})
			switch name {
			case "nil-source":
				source = nil
			case "nil-candidate":
				candidate = nil
			case "old-profile-removed":
				candidate.profiles = candidate.profiles[:len(candidate.profiles)-1]
			case "extra-policy":
				candidate.policies = append(candidate.policies, candidate.policies[0])
			case "invalid-use":
				intent.Use = ProfileUseNextDomainTransit
			case "empty-domain":
				intent.Domains = nil
			case "unknown-algorithm":
				intent.Algorithms = []Algorithm{"unknown"}
			case "duplicate-algorithm":
				intent.Algorithms = []Algorithm{AlgorithmEd25519SHA256, AlgorithmEd25519SHA256}
			case "noncanonical-selector":
				intent.Selectors = []string{"Selector"}
			}
			if _, err := ValidateCreateCandidateIntent(source, candidate, history, intent); err == nil {
				t.Fatal("unrequested or malformed create state accepted")
			}
		})
	}
}

// TestValidateCreateCandidateIntentRejectsCrossDomainKeyReuse keeps the new create allocation set globally fresh.
func TestValidateCreateCandidateIntentRejectsCrossDomainKeyReuse(t *testing.T) {
	for _, kind := range []string{"selector", "public-key"} {
		t.Run(kind, func(t *testing.T) {
			source, candidate, _, intent := createModelFixture(t, ProfileUseOriginator, []Algorithm{AlgorithmEd25519SHA256})
			second := testRecords(t, 3, "another.example", "second", AlgorithmEd25519SHA256)
			defer func() { _ = second.material.Close() }()
			first := credentialsForProfile(candidate, "profile-new")[0]
			if kind == "selector" {
				second.credential.selector = first.Selector()
			} else {
				material, _ := candidate.KeyMaterialByHandle(first.HandleID())
				defer func() { _ = material.Close() }()
				private := material.PrivatePKCS8DER()
				defer clear(private)
				reused, err := NewKeyMaterialDER(3, "tenant", "another.example", ProfileUseOriginator, second.handle.ID(), AlgorithmEd25519SHA256, first.PublicSPKIDER(), private)
				if err != nil {
					t.Fatal(err)
				}
				_ = second.material.Close()
				second.material = reused
				second.credential.publicSPKI = first.PublicSPKIDER()
			}
			materials := candidate.KeyMaterials()
			defer func() { closeKeyMaterials(materials) }()
			combined, err := NewGenerationWithState(3, DatasetStateStaging, append(candidate.Handles(), second.handle),
				append(candidate.Profiles(), second.profile), append(candidate.Credentials(), second.credential),
				append(candidate.Policies(), second.policy), append(materials, second.material))
			if kind == "selector" {
				// The existing generation constructor already enforces global selector uniqueness.
				if err == nil {
					_ = combined.Close()
					t.Fatal("duplicate selector passed generation validation")
				}
				return
			}
			if err != nil {
				t.Fatal("cross-domain fixture must be structurally valid", err)
			}
			defer func() { _ = combined.Close() }()
			// Both new policies must have the same requested feedback route.
			for index := range combined.policies {
				if combined.policies[index].domain == "another.example" {
					combined.policies[index].feedbackRouteID = intent.FeedbackRouteID
				}
			}
			intent.Domains = append(intent.Domains, "another.example")
			if _, err := ValidateCreateCandidateIntent(source, combined, lineageHistoryForGenerations(t, source, combined), intent); err == nil {
				t.Fatal("cross-domain create identity reuse was accepted")
			}
		})
	}
}
