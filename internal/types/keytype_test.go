package types

import "testing"

// TestDKIMKeyTypeParsesDKIM2OnlyValues proves the composite and all key types
// round-trip and are flagged as DKIM2-only, while legacy types are not.
func TestDKIMKeyTypeParsesDKIM2OnlyValues(t *testing.T) {
	for value, want := range map[string]DKIMKeyType{"composite": DKIMKeyTypeComposite, "all": DKIMKeyTypeAll} {
		got, err := ParseDKIMKeyType(value)
		if err != nil || got != want || got.String() != value || !got.RequiresDKIM2() {
			t.Fatalf("ParseDKIMKeyType(%q) = %v, %v", value, got, err)
		}
	}
	for _, legacy := range []DKIMKeyType{DKIMKeyTypeRSA, DKIMKeyTypeED25519, DKIMKeyTypeBoth} {
		if legacy.RequiresDKIM2() {
			t.Fatalf("%s flagged as DKIM2-only", legacy)
		}
	}
}
