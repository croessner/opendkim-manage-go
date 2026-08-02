package dkim2model

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

const (
	fixedEd25519PrivatePKCS8Hex = "302e020100300506032b657004220420" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	fixedEd25519PublicSPKIHex = "302a300506032b6570032100" +
		"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
)

func FuzzCanonicalDKIM2Scope(f *testing.F) {
	for _, seed := range []string{"example.test", "Example.TEST", "a-b.example", "a..example", "", "x.example."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 512 {
			t.Skip()
		}
		canonical, err := CanonicalDomain(input)
		if err != nil {
			return
		}
		if err := ValidateCanonicalDNSName(canonical); err != nil {
			t.Fatalf("canonical domain was rejected: %v", err)
		}
		second, err := CanonicalDomain(canonical)
		if err != nil || second != canonical {
			t.Fatal("domain canonicalization is not idempotent")
		}
	})
}

func FuzzKeyPairAndKeyMaterialOwnership(f *testing.F) {
	f.Add(false, false, byte(0))
	f.Add(true, false, byte(1))
	f.Add(false, true, byte(2))
	f.Fuzz(func(t *testing.T, closePairFirst, closeMaterialFirst bool, mutate byte) {
		privateDER, publicDER := fixedEd25519DER(t)
		defer clear(privateDER)
		defer clear(publicDER)
		pair, err := NewKeyPair(AlgorithmEd25519SHA256, privateDER, publicDER)
		if err != nil {
			t.Fatalf("fixed key fixture: %v", err)
		}
		material, err := NewKeyMaterial(1, "tenant", "example.test", ProfileUseOriginator, "handle", pair)
		if err != nil {
			_ = pair.Close()
			t.Fatal(err)
		}
		privateDER[0] ^= mutate
		publicDER[0] ^= mutate
		if closePairFirst {
			_ = pair.Close()
		}
		clone, err := material.Clone()
		if err != nil {
			_ = material.Close()
			_ = pair.Close()
			t.Fatalf("clone: %v", err)
		}
		if closeMaterialFirst {
			_ = material.Close()
		}
		if clone.Algorithm() != AlgorithmEd25519SHA256 || len(clone.PrivatePKCS8DER()) == 0 {
			t.Fatal("independent owner was invalidated")
		}
		_ = clone.Close()
		_ = material.Close()
		_ = pair.Close()
		if clone.Algorithm() != "" || material.Algorithm() != "" || pair.Algorithm() != "" {
			t.Fatal("closed protected owner remains readable")
		}
	})
}

func FuzzRotationPreservesUnselectedBinding(f *testing.F) {
	f.Add(byte(0))
	f.Add(byte(1))
	f.Fuzz(func(t *testing.T, choice byte) {
		current := fixedRotationGeneration(t)
		defer func() { _ = current.Close() }()
		original, err := current.Clone()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = original.Close() }()
		target, untouched := "one.example", "two.example"
		if choice%2 == 1 {
			target, untouched = untouched, target
		}
		candidate, err := PlanRotation(RotationPlan{
			Current: current, NextGeneration: 2, TenantID: "tenant", Domain: target,
			Use: ProfileUseOriginator, RSABits: DefaultRSABits, Random: &sequenceReader{value: choice},
			History: collisionSet{}, Generate: func(Algorithm, int, io.Reader) (*KeyPair, error) {
				privateDER, publicDER := fixedEd25519DER(t)
				defer clear(privateDER)
				defer clear(publicDER)
				return NewKeyPair(AlgorithmEd25519SHA256, privateDER, publicDER)
			},
		})
		if err != nil {
			t.Fatalf("rotation: %v", err)
		}
		defer func() { _ = candidate.Close() }()
		if !current.Equivalent(original) {
			t.Fatal("rotation mutated its current snapshot")
		}
		before, foundBefore := current.ProfileByDomain(untouched)
		after, foundAfter := candidate.ProfileByDomain(untouched)
		if !foundBefore || !foundAfter || before.ID() != after.ID() || before.Status() != after.Status() {
			t.Fatal("rotation changed the unselected profile")
		}
		beforeCredentials := credentialsForModelProfile(current, before.ID())
		afterCredentials := credentialsForModelProfile(candidate, after.ID())
		if len(beforeCredentials) != 1 || len(afterCredentials) != 1 ||
			beforeCredentials[0].Selector() != afterCredentials[0].Selector() ||
			beforeCredentials[0].HandleID() != afterCredentials[0].HandleID() ||
			!bytes.Equal(beforeCredentials[0].PublicSPKIDER(), afterCredentials[0].PublicSPKIDER()) {
			t.Fatal("rotation changed the unselected credential")
		}
		beforePolicy, afterPolicy := policyForModelDomain(current, untouched), policyForModelDomain(candidate, untouched)
		if beforePolicy.TenantID() != afterPolicy.TenantID() || beforePolicy.ProfileID() != afterPolicy.ProfileID() ||
			beforePolicy.Use() != afterPolicy.Use() || beforePolicy.Status() != afterPolicy.Status() ||
			beforePolicy.Rollout() != afterPolicy.Rollout() || beforePolicy.Compatibility() != afterPolicy.Compatibility() {
			t.Fatal("rotation changed the unselected policy")
		}
		beforeMaterial := fixedMaterialForDomain(t, current, untouched)
		afterMaterial := fixedMaterialForDomain(t, candidate, untouched)
		defer func() { _ = beforeMaterial.Close() }()
		defer func() { _ = afterMaterial.Close() }()
		beforePrivate, afterPrivate := beforeMaterial.PrivatePKCS8DER(), afterMaterial.PrivatePKCS8DER()
		defer clear(beforePrivate)
		defer clear(afterPrivate)
		if beforeMaterial.HandleID() != afterMaterial.HandleID() ||
			!bytes.Equal(beforeMaterial.PublicSPKIDER(), afterMaterial.PublicSPKIDER()) ||
			!bytes.Equal(beforePrivate, afterPrivate) {
			t.Fatal("rotation changed the unselected key material")
		}
	})
}

func TestRotationCollisionExhaustionProperty(t *testing.T) {
	current := fixedRotationGeneration(t)
	defer func() { _ = current.Close() }()
	history := &alwaysCollisionHistory{}
	candidate, err := PlanRotation(RotationPlan{
		Current: current, NextGeneration: 2, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, RSABits: DefaultRSABits, Random: &sequenceReader{}, History: history,
	})
	if err == nil || candidate != nil {
		t.Fatal("unbounded identifier collisions were accepted")
	}
	if history.selectorChecks != rotationAllocationAttempts || history.handleChecks != 0 {
		t.Fatalf("collision checks = selectors %d handles %d", history.selectorChecks, history.handleChecks)
	}
}

type alwaysCollisionHistory struct {
	selectorChecks int
	handleChecks   int
}

func (h *alwaysCollisionHistory) SelectorUsed(string) (bool, error) {
	h.selectorChecks++
	return true, nil
}

func (h *alwaysCollisionHistory) HandleUsed(string) (bool, error) {
	h.handleChecks++
	return true, nil
}

func fixedRotationGeneration(t *testing.T) *Generation {
	t.Helper()
	builder, err := NewBuilder(1, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	for index, domain := range []string{"one.example", "two.example"} {
		privateDER, publicDER := fixedEd25519DER(t)
		defer clear(privateDER)
		defer clear(publicDER)
		pair, err := NewKeyPair(AlgorithmEd25519SHA256, privateDER, publicDER)
		if err != nil {
			t.Fatal(err)
		}
		suffix := string(rune('1' + index))
		profile, err := NewProfile(1, "profile-"+suffix, domain, RecordStatusActive, time.Time{}, time.Time{})
		if err != nil {
			_ = pair.Close()
			t.Fatal(err)
		}
		handleID := "handle-" + suffix
		credential, err := NewCredential(1, profile.ID(), "selector-"+suffix, AlgorithmEd25519SHA256, pair.PublicSPKIDER(), handleID)
		if err != nil {
			_ = pair.Close()
			t.Fatal(err)
		}
		material, err := NewKeyMaterial(1, "tenant", domain, ProfileUseOriginator, handleID, pair)
		_ = pair.Close()
		if err != nil {
			t.Fatal(err)
		}
		policy, err := NewPolicy(1, "tenant", domain, ProfileUseOriginator, profile.ID(), RecordStatusActive, RolloutEnforce, CompatibilityStrict, "")
		if err != nil {
			_ = material.Close()
			t.Fatal(err)
		}
		if err := builder.AddProfileWithKeys(profile, []Credential{credential}, policy, []*KeyMaterial{material}); err != nil {
			_ = material.Close()
			t.Fatal(err)
		}
		_ = material.Close()
	}
	generation, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func fixedEd25519DER(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateDER, err := hex.DecodeString(fixedEd25519PrivatePKCS8Hex)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := hex.DecodeString(fixedEd25519PublicSPKIHex)
	if err != nil {
		clear(privateDER)
		t.Fatal(err)
	}
	return privateDER, publicDER
}

func fixedMaterialForDomain(t *testing.T, generation *Generation, domain string) *KeyMaterial {
	t.Helper()
	materials := generation.KeyMaterials()
	for _, material := range materials {
		if material.SigningDomain() == domain {
			for _, other := range materials {
				if other != material {
					_ = other.Close()
				}
			}
			return material
		}
	}
	closeKeyMaterials(materials)
	t.Fatal("fixed key material missing")
	return nil
}
