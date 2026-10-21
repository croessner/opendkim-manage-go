package dkim2store

import (
	"cmp"
	"slices"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// ValidRetainedRoots permits one contiguous v3 suffix after an unchanged contiguous legacy prefix.
// Only the legacy-to-v3 boundary may contain a retention gap; callers still enforce current and state fences.
func ValidRetainedRoots(roots []GenerationRoot) bool {
	if len(roots) == 0 {
		return false
	}
	ordered := slices.Clone(roots)
	slices.SortFunc(ordered, func(left, right GenerationRoot) int { return cmp.Compare(left.Number, right.Number) })
	for index, root := range ordered {
		if root.Number == 0 {
			return false
		}
		switch root.Schema {
		case legacySchemaVersion:
			if root.Number != 1 {
				return false
			}
		case dkim2model.SchemaVersion, dkim2model.SchemaVersionV3:
		default:
			return false
		}
		if index == 0 {
			continue
		}
		previous := ordered[index-1]
		if root.Number <= previous.Number || previous.Schema == dkim2model.SchemaVersionV3 && root.Schema != previous.Schema {
			return false
		}
		if root.Number-previous.Number != 1 &&
			(previous.Schema == dkim2model.SchemaVersionV3 || root.Schema != dkim2model.SchemaVersionV3) {
			return false
		}
	}
	return true
}
