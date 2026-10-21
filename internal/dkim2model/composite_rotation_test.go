package dkim2model

import (
	"io"
	"slices"
	"testing"
)

// planExtensionForTest rotates the one.example binding to the requested set.
func planExtensionForTest(t *testing.T, current *Generation, requested []Algorithm) (*Generation, error) {
	t.Helper()
	return PlanRotation(RotationPlan{
		Current: current, NextGeneration: current.Number() + 1, TenantID: "tenant", Domain: "one.example",
		Use: ProfileUseOriginator, Algorithms: requested, RSABits: DefaultRSABits,
		AllocationAttempts: 16, Random: &sequenceReader{}, History: collisionSet{},
		Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
			return GenerateKeyPair(algorithm, bits, nil)
		},
	})
}

// TestPlanRotationExtendsAlgorithmSetWithComposite proves a rotation may add
// mldsa44-ed25519-sha512 beside fresh RSA and Ed25519 keys, that lifecycle
// classification retires the two old keys and activates all three new ones,
// and that a rotation never drops an algorithm.
func TestPlanRotationExtendsAlgorithmSetWithComposite(t *testing.T) {
	current := activeBindingGeneration(t, 7, AlgorithmRSASHA256, AlgorithmEd25519SHA256)
	defer func() { _ = current.Close() }()
	candidate, err := planExtensionForTest(t, current, SigningAlgorithms())
	if err != nil {
		t.Fatalf("PlanRotation(extension) error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	credentials := credentialsForModelProfile(candidate, "profile-one")
	algorithms := make([]Algorithm, len(credentials))
	for index, credential := range credentials {
		algorithms[index] = credential.Algorithm()
	}
	if !slices.Equal(algorithms, SigningAlgorithms()) {
		t.Fatalf("candidate algorithms = %v", algorithms)
	}
	for _, credential := range credentials {
		for _, old := range credentialsForModelProfile(current, "profile-one") {
			if credential.Selector() == old.Selector() || credential.HandleID() == old.HandleID() {
				t.Fatal("rotation reused a predecessor selector or handle")
			}
		}
	}
	committed := rebasedGeneration(t, candidate, candidate.Number(), DatasetStateCommitted)
	defer func() { _ = committed.Close() }()
	binding, retiring, active, err := uniqueRotatedBinding(committed, current)
	if err != nil || binding.Domain() != "one.example" || len(retiring) != 2 || len(active) != 3 {
		t.Fatalf("uniqueRotatedBinding() retiring=%d active=%d error=%v", len(retiring), len(active), err)
	}

	if _, err := planExtensionForTest(t, current, []Algorithm{AlgorithmRSASHA256}); err == nil {
		t.Fatal("rotation dropped an algorithm")
	}
	if _, err := planExtensionForTest(t, current, []Algorithm{AlgorithmEd25519SHA256, AlgorithmMLDSA44Ed25519SHA512}); err == nil {
		t.Fatal("rotation dropped RSA while adding the composite")
	}
	if _, _, _, err := uniqueRotatedBinding(current, committed); err == nil {
		t.Fatal("classification accepted a successor that removes algorithms")
	}
}

// successorKeySpec describes one credential of a hand-built successor; a nil
// fresh pair reuses the predecessor key of the same algorithm.
type successorKeySpec struct {
	algorithm Algorithm
	selector  string
	handle    string
	use       ProfileUse
	reuse     bool
}

// buildSuccessorForTest constructs one committed successor of the one.example
// binding with exactly the given credential specs, bypassing PlanRotation so
// classification sees deliberately malformed candidates.
func buildSuccessorForTest(t *testing.T, predecessor *Generation, specs []successorKeySpec) (*Generation, error) {
	t.Helper()
	number := predecessor.Number() + 1
	builder, err := predecessor.NextBuilder(number, DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	oldMaterials := map[Algorithm]*KeyMaterial{}
	for _, material := range predecessor.KeyMaterials() {
		oldMaterials[material.Algorithm()] = material
	}
	var credentials []Credential
	var materials []*KeyMaterial
	defer func() { closeKeyMaterials(materials) }()
	for _, spec := range specs {
		use := spec.use
		if use == "" {
			use = ProfileUseOriginator
		}
		var material *KeyMaterial
		if spec.reuse {
			old := oldMaterials[spec.algorithm]
			material, err = NewKeyMaterialDER(number, "tenant", "one.example", use, spec.handle, spec.algorithm, old.PublicSPKIDER(), old.PrivatePKCS8DER())
		} else {
			pair, pairErr := GenerateKeyPair(spec.algorithm, DefaultRSABits, nil)
			if pairErr != nil {
				t.Fatal(pairErr)
			}
			material, err = NewKeyMaterial(number, "tenant", "one.example", use, spec.handle, pair)
			_ = pair.Close()
		}
		if err != nil {
			return nil, err
		}
		credential, credentialErr := NewCredential(number, "profile-one", spec.selector, spec.algorithm, material.PublicSPKIDER(), spec.handle)
		if credentialErr != nil {
			_ = material.Close()
			return nil, credentialErr
		}
		credentials = append(credentials, credential)
		materials = append(materials, material)
	}
	if err := builder.ReplaceProfileKeys("profile-one", credentials, materials); err != nil {
		return nil, err
	}
	materials = nil
	return builder.Build()
}

// TestUniqueRotatedBindingRejectsMalformedExtensions pins the invariants the
// extension relaxation rests on: an unchanged profile cannot gain an
// algorithm, and an added credential needs a fresh handle and selector and
// key material of the replaced binding.
func TestUniqueRotatedBindingRejectsMalformedExtensions(t *testing.T) {
	predecessor := activeBindingGeneration(t, 7, AlgorithmRSASHA256, AlgorithmEd25519SHA256)
	defer func() { _ = predecessor.Close() }()
	fresh := func(composite successorKeySpec) []successorKeySpec {
		return []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-new-rsa", handle: "handle-new-rsa"},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			composite,
		}
	}
	valid, err := buildSuccessorForTest(t, predecessor, fresh(successorKeySpec{
		algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := uniqueRotatedBinding(valid, predecessor); err != nil {
		t.Fatalf("valid extension rejected: %v", err)
	}
	_ = valid.Close()
	for _, test := range []struct {
		name  string
		specs []successorKeySpec
	}{
		{name: "unchanged keys gain composite", specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-one-rsa", handle: "handle-one-rsa", reuse: true},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-one-ed", handle: "handle-one-ed", reuse: true},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq"},
		}},
		{name: "added credential reuses old handle", specs: fresh(successorKeySpec{
			algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-one-ed"})},
		{name: "added credential reuses old selector", specs: fresh(successorKeySpec{
			algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-one-ed", handle: "handle-new-pq"})},
		{name: "added material for another use", specs: fresh(successorKeySpec{
			algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq",
			use: ProfileUseOrdinaryTransit})},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := buildSuccessorForTest(t, predecessor, test.specs)
			if err != nil {
				return // the generation builder already refuses the shape
			}
			defer func() { _ = candidate.Close() }()
			if _, _, _, err := uniqueRotatedBinding(candidate, predecessor); err == nil {
				t.Fatal("malformed extension classified as a valid rotation")
			}
		})
	}
}
