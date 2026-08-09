package dkim2store

import (
	"bytes"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

func TestGenerationPurgePlanCanonicalRoundTripAndTamperFence(t *testing.T) {
	candidate := testGeneration(t, 2, dkim2model.DatasetStateCommitted, "one.example")
	defer func() { _ = candidate.Close() }()
	operation, err := dkim2model.GenerateOperationID(bytes.NewReader(bytes.Repeat([]byte{9}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, 1, candidate)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGenerationPurgePlan(GenerationInventory{Current: 3, Roots: []GenerationInventoryRoot{{
		Number: 2, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted,
		WasActive: true, Complete: true, Metadata: metadata,
	}}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	document, err := MarshalGenerationPurgePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGenerationPurgePlan(document, 4096)
	if err != nil || !plan.equal(parsed) {
		t.Fatalf("round trip = %v", err)
	}
	tampered := append([]byte(nil), document...)
	for index := range tampered {
		if tampered[index] == '3' {
			tampered[index] = '4'
			break
		}
	}
	if _, err := ParseGenerationPurgePlan(tampered, 4096); err == nil {
		t.Fatal("tampered purge plan was accepted")
	}
	if _, err := ParseGenerationPurgePlan(append(document, '\n'), 4096); err == nil {
		t.Fatal("non-canonical purge plan was accepted")
	}
}
