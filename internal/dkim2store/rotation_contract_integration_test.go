package dkim2store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// TestLDAPV2RepositoryContractHarness validates the repository against the
// pinned schema shape in memory. It is intentionally not an LDAP end-to-end
// claim; a real slapd integration requires the separately documented binary.
func TestLDAPV2RepositoryContractHarness(t *testing.T) {
	schemaAttributes, schemaClasses := loadPinnedSchemaNames(t)
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	current := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
	defer func() { _ = current.Close() }()
	if err := repository.Publish(context.Background(), 0, current); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	assertRequestsUsePinnedSchema(t, executor.adds, schemaAttributes, schemaClasses)

	loaded, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	defer func() { _ = loaded.Close() }()
	assertCompleteBinaryRoundTrip(t, current, loaded)

	candidate := successorGeneration(t, loaded, 2)
	defer func() { _ = candidate.Close() }()
	prepared, err := repository.Stage(context.Background(), candidate, 8)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if got := executor.entries[dnKey("cn=current,"+testBaseDN)].GetAttributeValue(attributeGeneration); got != "1" {
		t.Fatalf("staging moved current to %q", got)
	}
	stored, err := prepared.Generation()
	if err != nil {
		t.Fatalf("prepared generation: %v", err)
	}
	assertCompleteBinaryRoundTrip(t, candidate, stored)
	_ = stored.Close()

	restarted := mustRepository(t, executor)
	resumed, err := restarted.LoadPending(context.Background(), 2, 8)
	if err != nil {
		t.Fatalf("restart/resume: %v", err)
	}
	defer func() { _ = resumed.Close() }()
	if resumed.ExpectedCurrent() != 1 || resumed.ObservedCurrent() != 1 {
		t.Fatalf("resume fence = expected %d observed %d", resumed.ExpectedCurrent(), resumed.ObservedCurrent())
	}

	before := len(executor.modifies)
	if err := restarted.CommitAndSwitch(context.Background(), 2, 8); err != nil {
		t.Fatalf("commit and switch: %v", err)
	}
	if len(executor.modifies) != before+2 {
		t.Fatalf("commit/switch modify count = %d", len(executor.modifies)-before)
	}
	for _, request := range executor.modifies[before:] {
		assertCriticalAssertion(t, request)
	}
	final, err := restarted.LoadPending(context.Background(), 2, 8)
	if err != nil {
		t.Fatalf("activated readback: %v", err)
	}
	defer func() { _ = final.Close() }()
	if final.ObservedCurrent() != 2 {
		t.Fatalf("activated pointer = %d", final.ObservedCurrent())
	}
}

func TestLDAPRecordCNMatchesProviderWireContract(t *testing.T) {
	for index, want := range []string{"record-1", "record-2", "record-3"} {
		if got := recordCN(index); got != want {
			t.Fatalf("recordCN(%d) = %q, want %q", index, got, want)
		}
	}
	for _, test := range []struct {
		name   string
		value  string
		schema string
		valid  bool
	}{
		{name: "v2 canonical", value: "1", schema: dkim2model.SchemaVersion, valid: true},
		{name: "v2 rejects v3", value: "record-1", schema: dkim2model.SchemaVersion},
		{name: "v3 canonical", value: "record-1", schema: dkim2model.SchemaVersionV3, valid: true},
		{name: "v3 rejects v2", value: "1", schema: dkim2model.SchemaVersionV3},
		{name: "v3 rejects leading zero", value: "record-01", schema: dkim2model.SchemaVersionV3},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseStorageRecordCN(test.value, test.schema)
			if (err == nil) != test.valid {
				t.Fatalf("parseStorageRecordCN(%q, %q) error = %v", test.value, test.schema, err)
			}
		})
	}
}

func TestLDAPV2RepositoryContractRejectsPartialAndConcurrentPublication(t *testing.T) {
	t.Run("partial staging", func(t *testing.T) {
		executor, _, candidate := stagedSuccessor(t)
		defer func() { _ = candidate.Close() }()
		for key, entry := range executor.entries {
			if strings.Contains(entry.DN, "dkim2Generation=2") && hasObjectClass(entry, classKeyMaterial) {
				delete(executor.entries, key)
				break
			}
		}
		if _, err := mustRepository(t, executor).LoadPending(context.Background(), 2, 8); !errors.Is(err, ErrMalformed) {
			t.Fatalf("partial staging error = %v", err)
		}
	})

	t.Run("two publishers", func(t *testing.T) {
		executor, repository, candidate := stagedSuccessor(t)
		defer func() { _ = candidate.Close() }()
		beforeAdds, beforeModifies := len(executor.adds), len(executor.modifies)
		if _, err := mustRepository(t, executor).Stage(context.Background(), candidate, 8); !errors.Is(err, ErrConflict) {
			t.Fatalf("second publisher error = %v", err)
		}
		if len(executor.adds) != beforeAdds || len(executor.modifies) != beforeModifies {
			t.Fatal("second publisher performed a write")
		}
		setEntryAttribute(executor.entries[dnKey("cn=current,"+testBaseDN)], attributeGeneration, []string{"3"})
		if err := repository.CommitAndSwitch(context.Background(), 2, 8); !errors.Is(err, ErrConflict) {
			t.Fatalf("concurrent pointer error = %v", err)
		}
	})

	t.Run("critical current assertion", func(t *testing.T) {
		executor, repository, candidate := stagedSuccessor(t)
		defer func() { _ = candidate.Close() }()
		baseline := len(executor.modifies)
		executor.failModifyAt = baseline + 2
		executor.modifyError = ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("synthetic concurrent publisher"))
		if err := repository.CommitAndSwitch(context.Background(), 2, 8); !errors.Is(err, ErrConflict) {
			t.Fatalf("current assertion error = %v", err)
		}
		if len(executor.modifies) != baseline+2 {
			t.Fatal("current assertion failure was blindly retried")
		}
		assertCriticalAssertion(t, executor.modifies[baseline])
		assertCriticalAssertion(t, executor.modifies[baseline+1])
		if got := executor.entries[dnKey("cn=current,"+testBaseDN)].GetAttributeValue(attributeGeneration); got != "1" {
			t.Fatalf("failed current assertion moved pointer to %q", got)
		}
	})
}

func TestLDAPV2RepositoryContractRecoversCommittedUnreachable(t *testing.T) {
	executor, repository, candidate := stagedSuccessor(t)
	defer func() { _ = candidate.Close() }()
	if err := repository.commitGeneration(context.Background(), 2); err != nil {
		t.Fatalf("commit root: %v", err)
	}
	if got := executor.entries[dnKey("cn=current,"+testBaseDN)].GetAttributeValue(attributeGeneration); got != "1" {
		t.Fatalf("root commit moved current to %q", got)
	}
	restarted := mustRepository(t, executor)
	prepared, err := restarted.LoadPending(context.Background(), 2, 8)
	if err != nil {
		t.Fatalf("load committed-unreachable: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	stored, err := prepared.Generation()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stored.Close() }()
	if prepared.ObservedCurrent() != 1 || stored.State() != dkim2model.DatasetStateCommitted {
		t.Fatalf("recovery state = current %d state %q", prepared.ObservedCurrent(), stored.State())
	}
	if err := restarted.CommitAndSwitch(context.Background(), 2, 8); err != nil {
		t.Fatalf("resume pointer switch: %v", err)
	}
}

func TestLDAPV2RepositoryContractDoesNotFormatProtectedMaterial(t *testing.T) {
	_, repository, candidate := stagedSuccessor(t)
	defer func() { _ = candidate.Close() }()
	prepared, err := repository.LoadPending(context.Background(), 2, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prepared.Close() }()
	materials := candidate.KeyMaterials()
	defer closeTestMaterials(materials)
	privateMarker := fmt.Sprintf("%x", materials[0].PrivatePKCS8DER())
	for _, value := range []any{candidate, prepared, materials[0]} {
		for _, output := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(output, privateMarker) || strings.Contains(output, materials[0].HandleID()) {
				t.Fatalf("protected formatter leaked data for %T", value)
			}
		}
	}
}

func loadPinnedSchemaNames(t *testing.T) (map[string]struct{}, map[string]struct{}) {
	t.Helper()
	raw, err := os.ReadFile("testdata/rnsdkim2.schema")
	if err != nil {
		t.Fatal(err)
	}
	attributePattern := regexp.MustCompile(`(?m)^attributetype .* NAME '([^']+)'`)
	classPattern := regexp.MustCompile(`(?m)^objectclass .* NAME '([^']+)'`)
	attributes := map[string]struct{}{"objectclass": {}, "cn": {}, "ou": {}}
	classes := map[string]struct{}{"top": {}, "organizationalunit": {}}
	for _, match := range attributePattern.FindAllSubmatch(raw, -1) {
		attributes[strings.ToLower(string(match[1]))] = struct{}{}
	}
	for _, match := range classPattern.FindAllSubmatch(raw, -1) {
		classes[strings.ToLower(string(match[1]))] = struct{}{}
	}
	if len(attributes) != 25 || len(classes) != 9 || !bytes.Contains(raw, []byte("dkim2-datasource-v3")) {
		t.Fatal("pinned schema fixture is incomplete")
	}
	return attributes, classes
}

func assertRequestsUsePinnedSchema(t *testing.T, requests []*ldap.AddRequest, attributes, classes map[string]struct{}) {
	t.Helper()
	seenClasses := make(map[string]struct{})
	for _, request := range requests {
		for _, attribute := range request.Attributes {
			if _, ok := attributes[strings.ToLower(attribute.Type)]; !ok {
				t.Fatalf("attribute %q is outside pinned schema", attribute.Type)
			}
			if strings.EqualFold(attribute.Type, attributeObjectClass) {
				for _, class := range attribute.Vals {
					if _, ok := classes[strings.ToLower(class)]; !ok {
						t.Fatalf("object class %q is outside pinned schema", class)
					}
					seenClasses[strings.ToLower(class)] = struct{}{}
				}
			}
			if strings.EqualFold(attribute.Type, attributeSchemaVersion) &&
				(len(attribute.Vals) != 1 || attribute.Vals[0] != dkim2model.SchemaVersion) {
				t.Fatal("repository emitted a non-v2 schema marker")
			}
		}
	}
	want := []string{"dkim2credential", "dkim2dataset", "dkim2handle", "dkim2keymaterial", "dkim2policy", "dkim2profile", "organizationalunit", "top"}
	got := make([]string, 0, len(seenClasses))
	for class := range seenClasses {
		got = append(got, class)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("schema classes = %v, want %v", got, want)
	}
}

func assertCompleteBinaryRoundTrip(t *testing.T, want, got *dkim2model.Generation) {
	t.Helper()
	if want == nil || got == nil {
		t.Fatal("generation roundtrip changed immutable data")
	}
	wantMaterials, gotMaterials := want.KeyMaterials(), got.KeyMaterials()
	defer closeTestMaterials(wantMaterials)
	defer closeTestMaterials(gotMaterials)
	normalized, err := dkim2model.NewGenerationWithState(
		want.Number(), got.State(), want.Handles(), want.Profiles(), want.Credentials(), want.Policies(), wantMaterials,
	)
	if err != nil {
		t.Fatalf("normalize generation: %v", err)
	}
	defer func() { _ = normalized.Close() }()
	if !normalized.Equivalent(got) {
		t.Fatal("generation roundtrip changed immutable data")
	}
	if len(wantMaterials) != len(gotMaterials) {
		t.Fatalf("material cardinality = %d, want %d", len(gotMaterials), len(wantMaterials))
	}
	for index := range wantMaterials {
		wantPrivate, gotPrivate := wantMaterials[index].PrivatePKCS8DER(), gotMaterials[index].PrivatePKCS8DER()
		wantPublic, gotPublic := wantMaterials[index].PublicSPKIDER(), gotMaterials[index].PublicSPKIDER()
		if !bytes.Equal(wantPrivate, gotPrivate) || !bytes.Equal(wantPublic, gotPublic) {
			t.Fatalf("binary material %d changed", index)
		}
		clear(wantPrivate)
		clear(gotPrivate)
		clear(wantPublic)
		clear(gotPublic)
	}
}

func assertCriticalAssertion(t *testing.T, request *ldap.ModifyRequest) {
	t.Helper()
	if request == nil || len(request.Controls) != 1 {
		t.Fatal("modify lacks one assertion control")
	}
	control, ok := request.Controls[0].(*ldap.ControlString)
	if !ok || control.ControlType != assertionControlOID || !control.Criticality || control.ControlValue == "" {
		t.Fatal("modify lacks a critical RFC 4528 assertion")
	}
}

func closeTestMaterials(materials []*dkim2model.KeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}
