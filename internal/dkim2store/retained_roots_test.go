package dkim2store

import (
	"reflect"
	"slices"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// TestValidRetainedRootsSharesOnlyTheLegacyBoundaryGap rejects every other missing or ambiguous root.
func TestValidRetainedRootsSharesOnlyTheLegacyBoundaryGap(t *testing.T) {
	v1 := func(number uint64) GenerationRoot { return GenerationRoot{Number: number, Schema: legacySchemaVersion} }
	v2 := func(number uint64) GenerationRoot {
		return GenerationRoot{Number: number, Schema: dkim2model.SchemaVersion}
	}
	v3 := func(number uint64) GenerationRoot {
		return GenerationRoot{Number: number, Schema: dkim2model.SchemaVersionV3}
	}
	for _, test := range []struct {
		name  string
		roots []GenerationRoot
		valid bool
	}{
		{"empty", nil, false},
		{"v2-only", []GenerationRoot{v2(8), v2(9)}, true},
		{"v3-only", []GenerationRoot{v3(8), v3(9)}, true},
		{"bootstrap", []GenerationRoot{v1(1), v2(2), v3(3)}, true},
		{"bootstrap-gap", []GenerationRoot{v1(1), v3(6), v3(7)}, true},
		{"transition", []GenerationRoot{v2(8), v3(9), v3(10)}, true},
		{"retention-gap", []GenerationRoot{v2(8), v2(9), v3(12), v3(13)}, true},
		{"unordered", []GenerationRoot{v3(13), v2(9), v3(12), v2(8)}, true},
		{"exhausted-range", []GenerationRoot{v3(^uint64(0) - 1), v3(^uint64(0))}, true},
		{"zero", []GenerationRoot{v3(0)}, false},
		{"duplicate", []GenerationRoot{v2(8), v3(8)}, false},
		{"unknown-schema", []GenerationRoot{{Number: 8, Schema: "unknown"}}, false},
		{"absent-schema", []GenerationRoot{{Number: 8}}, false},
		{"unknown-boundary", []GenerationRoot{{Number: 8}, v3(12)}, false},
		{"v1-outside-bootstrap", []GenerationRoot{v1(2), v3(3)}, false},
		{"legacy-hole", []GenerationRoot{v2(8), v2(10), v3(12)}, false},
		{"bootstrap-legacy-hole", []GenerationRoot{v1(1), v2(3), v3(4)}, false},
		{"v3-hole", []GenerationRoot{v3(8), v3(10)}, false},
		{"v3-interior-hole", []GenerationRoot{v2(8), v3(12), v3(14)}, false},
		{"legacy-after-v3", []GenerationRoot{v3(8), v2(9)}, false},
		{"legacy-within-v3", []GenerationRoot{v2(8), v3(12), v2(13), v3(14)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := slices.Clone(test.roots)
			inventory := make([]GenerationInventoryRoot, len(test.roots))
			for index, root := range test.roots {
				inventory[index] = GenerationInventoryRoot{Number: root.Number, Schema: root.Schema}
			}
			if ValidRetainedRoots(test.roots) != test.valid || contiguousGenerationRoots(test.roots) != test.valid ||
				contiguousInventorySuffix(inventory) != test.valid {
				t.Fatal("inventory, history, and public shape validation disagree with the exact schema boundary")
			}
			if !reflect.DeepEqual(test.roots, before) {
				t.Fatal("shape validation changed the caller's root ordering")
			}
		})
	}
}

// TestRetainedRootCurrentAndPendingFencesRemainExact keeps generation and state authorization separate from retention shape.
func TestRetainedRootCurrentAndPendingFencesRemainExact(t *testing.T) {
	roots := []GenerationRoot{
		{Number: 1, Schema: dkim2model.SchemaVersion, State: dkim2model.DatasetStateCommitted},
		{Number: 4, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted},
		{Number: 5, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateCommitted},
	}
	if !historyHasExactCurrentMaximum(roots, 5) || historyHasExactCurrentMaximum(roots, 4) ||
		historyHasExactCurrentMaximum(roots, 6) || historyHasExactCurrentMaximum(roots, 0) {
		t.Fatal("current maximum fence changed")
	}
	pending := append(slices.Clone(roots), GenerationRoot{Number: 6, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateStaging})
	if !historyHasPendingShape(pending, 5, 6) || historyHasPendingShape(pending, 4, 6) ||
		historyHasPendingShape(pending, 6, 7) || historyHasExactCurrentMaximum(pending, 6) {
		t.Fatal("pending successor or staging fence changed")
	}
	pending[1].State = dkim2model.DatasetStateStaging
	if historyHasPendingShape(pending, 5, 6) {
		t.Fatal("uncommitted predecessor accepted")
	}
	pending[1].State = dkim2model.DatasetStateCommitted
	pending = append(pending, GenerationRoot{Number: 7, Schema: dkim2model.SchemaVersionV3, State: dkim2model.DatasetStateStaging})
	if historyHasPendingShape(pending, 5, 6) {
		t.Fatal("foreign higher candidate accepted")
	}
}
