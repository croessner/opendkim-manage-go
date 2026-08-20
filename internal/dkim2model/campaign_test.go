package dkim2model

import (
	"io"
	"testing"
	"time"
)

func TestChangedActiveBindingsAcceptsCompleteMultiBindingSuccessor(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	candidate, _, err := PlanGlobalRotation(GlobalRotationPlan{Current: source, NextGeneration: 2,
		Now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC), History: lineageHistoryForGenerations(t, source),
		Identifiers: collisionSet{}, Random: &sequenceReader{}, Limits: RotationLimits{RotateAfter: 30 * 24 * time.Hour,
			MaximumClockSkew: 5 * time.Minute, AllocationAttempts: 16, RSABits: DefaultRSABits, MaximumBindings: 10},
		Generate: func(a Algorithm, bits int, _ io.Reader) (*KeyPair, error) { return GenerateKeyPair(a, bits, nil) }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = candidate.Close() }()
	changed, err := ChangedActiveBindings(source, candidate, 10)
	if err != nil || len(changed) != 2 || changed[0].Domain() != "one.example" || changed[1].Domain() != "two.example" {
		t.Fatalf("changed = %#v, %v", changed, err)
	}
}

func TestActiveBindingsReturnsEveryBoundedCurrentBinding(t *testing.T) {
	current := activeRotationGeneration(t)
	defer func() { _ = current.Close() }()

	bindings, err := ActiveBindings(current, 2)
	if err != nil || len(bindings) != 2 || bindings[0].Domain() != "one.example" || bindings[1].Domain() != "two.example" {
		t.Fatalf("bindings = %#v, %v", bindings, err)
	}
	if unbounded, boundedErr := ActiveBindings(current, 1); boundedErr == nil || unbounded != nil {
		t.Fatal("active binding inventory exceeded its configured bound")
	}
}

func TestChangedActiveBindingsRejectsUnrelatedMutation(t *testing.T) {
	source := activeRotationGeneration(t)
	defer func() { _ = source.Close() }()
	builder, err := source.NextBuilder(2, DatasetStateStaging)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	profile, _ := source.ProfileByDomain("two.example")
	changedProfile, err := NewProfile(2, profile.ID(), profile.SigningDomain(), profile.Status(),
		time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.ReplaceProfile(changedProfile); err != nil {
		t.Fatal(err)
	}
	candidate, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = candidate.Close() }()
	if changed, validateErr := ChangedActiveBindings(source, candidate, 10); validateErr == nil || changed != nil {
		t.Fatal("unrelated profile mutation accepted")
	}
}
