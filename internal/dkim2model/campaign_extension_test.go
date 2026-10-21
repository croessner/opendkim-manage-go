package dkim2model

import (
	"io"
	"slices"
	"testing"
	"time"
)

// extensionPlanForTest returns a deterministic global extension plan for current.
func extensionPlanForTest(current *Generation, requested []Algorithm) GlobalExtensionPlan {
	return GlobalExtensionPlan{
		Current: current, NextGeneration: current.Number() + 1, Algorithms: requested,
		Identifiers: collisionSet{}, Random: &sequenceReader{},
		Limits: RotationLimits{RotateAfter: 30 * 24 * time.Hour, MaximumClockSkew: 5 * time.Minute,
			AllocationAttempts: 16, RSABits: DefaultRSABits, MaximumBindings: 10},
		Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
			return GenerateKeyPair(algorithm, bits, nil)
		},
	}
}

// TestPlanGlobalExtensionReplacesEveryBindingWithTheRequestedSet proves that
// one extension campaign fully replaces every active binding with fresh keys
// of the requested superset and that campaign successor validation accepts it.
func TestPlanGlobalExtensionReplacesEveryBindingWithTheRequestedSet(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	candidate, bindings, err := PlanGlobalExtension(extensionPlanForTest(source, SigningAlgorithms()))
	if err != nil || candidate == nil {
		t.Fatalf("PlanGlobalExtension() error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	if len(bindings) != 2 || bindings[0].Domain() != "one.example" || bindings[1].Domain() != "two.example" {
		t.Fatalf("bindings = %d", len(bindings))
	}
	for _, profileID := range []string{"profile-one", "profile-two"} {
		credentials := credentialsForModelProfile(candidate, profileID)
		algorithms := make([]Algorithm, len(credentials))
		for index, credential := range credentials {
			algorithms[index] = credential.Algorithm()
			for _, old := range source.Credentials() {
				if credential.Selector() == old.Selector() || credential.HandleID() == old.HandleID() {
					t.Fatal("extension reused a source selector or handle")
				}
			}
		}
		slices.SortFunc(algorithms, CompareAlgorithms)
		if !slices.Equal(algorithms, SigningAlgorithms()) {
			t.Fatalf("%s algorithms = %v", profileID, algorithms)
		}
	}
	changed, err := ChangedActiveBindings(source, candidate, 10)
	if err != nil || len(changed) != 2 {
		t.Fatalf("ChangedActiveBindings() = %d, %v", len(changed), err)
	}
}

// TestPlanGlobalExtensionRefusesToShrinkAnyBinding proves that a requested set
// missing an algorithm of any active binding rejects the whole campaign.
func TestPlanGlobalExtensionRefusesToShrinkAnyBinding(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	for _, requested := range [][]Algorithm{
		{AlgorithmEd25519SHA256},
		{AlgorithmEd25519SHA256, AlgorithmMLDSA44Ed25519SHA512},
		nil,
		{AlgorithmEd25519SHA256, AlgorithmEd25519SHA256, AlgorithmRSASHA256},
		{AlgorithmRSASHA256, AlgorithmEd25519SHA256, Algorithm("unknown")},
	} {
		candidate, bindings, err := PlanGlobalExtension(extensionPlanForTest(source, requested))
		if err == nil || candidate != nil || bindings != nil {
			if candidate != nil {
				_ = candidate.Close()
			}
			t.Fatalf("extension %v accepted", requested)
		}
	}
}

// TestPlanGlobalExtensionIsIdleWhenEveryBindingHasTheRequestedSet proves an
// already extended dataset is not rotated again by a repeated campaign.
func TestPlanGlobalExtensionIsIdleWhenEveryBindingHasTheRequestedSet(t *testing.T) {
	source := activeBindingGeneration(t, 7, SigningAlgorithms()...)
	defer func() { _ = source.Close() }()
	candidate, bindings, err := PlanGlobalExtension(extensionPlanForTest(source, SigningAlgorithms()))
	if err != nil || candidate != nil || bindings != nil {
		t.Fatalf("idle extension candidate=%v bindings=%d err=%v", candidate != nil, len(bindings), err)
	}
}

// TestChangedActiveBindingsAcceptsOnlyCompleteExtensions pins the campaign
// successor rules for algorithm-set extensions: every credential is fresh,
// every source algorithm survives, and no selector or handle is reused.
func TestChangedActiveBindingsAcceptsOnlyCompleteExtensions(t *testing.T) {
	source := activeBindingGeneration(t, 7, AlgorithmRSASHA256, AlgorithmEd25519SHA256)
	defer func() { _ = source.Close() }()
	for _, test := range []struct {
		name   string
		specs  []successorKeySpec
		accept bool
	}{
		{name: "complete fresh extension", accept: true, specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-new-rsa", handle: "handle-new-rsa"},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq"},
		}},
		{name: "retained source credential", specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-one-rsa", handle: "handle-one-rsa", reuse: true},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq"},
		}},
		{name: "dropped algorithm", specs: []successorKeySpec{
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq"},
		}},
		{name: "shrunk set", specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-new-rsa", handle: "handle-new-rsa"},
		}},
		{name: "added credential reuses source selector", specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-new-rsa", handle: "handle-new-rsa"},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-one-ed", handle: "handle-new-pq"},
		}},
		{name: "added credential reuses source handle", specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-new-rsa", handle: "handle-new-rsa"},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-one-ed"},
		}},
		{name: "added credential for another use", specs: []successorKeySpec{
			{algorithm: AlgorithmRSASHA256, selector: "selector-new-rsa", handle: "handle-new-rsa"},
			{algorithm: AlgorithmEd25519SHA256, selector: "selector-new-ed", handle: "handle-new-ed"},
			{algorithm: AlgorithmMLDSA44Ed25519SHA512, selector: "selector-new-pq", handle: "handle-new-pq", use: ProfileUseDeliveryStatus},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, buildErr := buildSuccessorForTest(t, source, test.specs)
			if buildErr != nil {
				if test.accept {
					t.Fatalf("fixture build error = %v", buildErr)
				}
				return
			}
			defer func() { _ = candidate.Close() }()
			changed, err := ChangedActiveBindings(source, candidate, 10)
			if test.accept != (err == nil) {
				t.Fatalf("ChangedActiveBindings() accept=%v error=%v", test.accept, err)
			}
			if test.accept && (len(changed) != 1 || changed[0].Domain() != "one.example") {
				t.Fatalf("changed = %d", len(changed))
			}
		})
	}
}

// TestValidateExtensionCandidateRequiresEveryBindingAndTheExactSet proves the
// resume check binds a stored candidate to the requested extension.
func TestValidateExtensionCandidateRequiresEveryBindingAndTheExactSet(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	candidate, _, err := PlanGlobalExtension(extensionPlanForTest(source, SigningAlgorithms()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = candidate.Close() }()
	if err := ValidateExtensionCandidate(source, candidate, SigningAlgorithms(), 10); err != nil {
		t.Fatalf("ValidateExtensionCandidate(all) error = %v", err)
	}
	if err := ValidateExtensionCandidate(source, candidate, []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}, 10); err == nil {
		t.Fatal("stored extension accepted for a different requested set")
	}
	partial, err := PlanRotation(RotationPlan{
		Current: source, NextGeneration: 2, TenantID: "tenant", Domain: "one.example", Use: ProfileUseOriginator,
		Algorithms: SigningAlgorithms(), RSABits: DefaultRSABits, AllocationAttempts: 16,
		Random: &sequenceReader{}, History: collisionSet{},
		Generate: func(algorithm Algorithm, bits int, _ io.Reader) (*KeyPair, error) {
			return GenerateKeyPair(algorithm, bits, nil)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = partial.Close() }()
	if err := ValidateExtensionCandidate(source, partial, SigningAlgorithms(), 10); err == nil {
		t.Fatal("stored candidate leaving an active binding unrotated accepted")
	}
}
