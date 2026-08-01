package dkim2store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const testBaseDN = "ou=dkim2,dc=example,dc=org"

func TestLDAPRepositoryBootstrapPublishesCompleteGenerationWithCriticalFence(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
	defer func() { _ = candidate.Close() }()

	if err := repository.Publish(context.Background(), 0, candidate); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if len(executor.adds) != 17 { // pointer + root + five OUs + five records per domain
		t.Fatalf("add count = %d, want 17", len(executor.adds))
	}
	if len(executor.modifies) != 2 {
		t.Fatalf("modify count = %d, want 2", len(executor.modifies))
	}
	assertion := executor.modifies[1]
	if assertion.DN != "cn=current,"+testBaseDN || len(assertion.Controls) != 1 {
		t.Fatalf("unexpected current fence: %#v", assertion)
	}
	control, ok := assertion.Controls[0].(*ldap.ControlString)
	if !ok || control.ControlType != assertionControlOID || !control.Criticality || control.ControlValue == "" {
		t.Fatalf("assertion control is not critical RFC 4528: %#v", assertion.Controls[0])
	}

	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent() error = %v", err)
	}
	defer func() { _ = current.Close() }()
	materials := current.KeyMaterials()
	defer func() {
		for _, material := range materials {
			_ = material.Close()
		}
	}()
	if current.Number() != 1 || current.State() != dkim2model.DatasetStateCommitted ||
		len(current.Profiles()) != 2 || len(materials) != 2 {
		t.Fatalf("loaded generation is incomplete")
	}
	for _, request := range executor.searches {
		if request.DerefAliases != ldap.NeverDerefAliases || request.SizeLimit <= 0 ||
			!request.EnforceSizeLimit || request.TimeLimit <= 0 {
			t.Fatalf("unbounded or alias-following request: %#v", request)
		}
		for _, attribute := range request.Attributes {
			if attribute == "*" || attribute == "+" {
				t.Fatalf("broad attribute request: %#v", request.Attributes)
			}
		}
	}
	if executor.lastGenerationResult == nil {
		t.Fatal("missing staged readback evidence")
	}
	for _, entry := range executor.lastGenerationResult.Entries {
		for _, attribute := range entry.Attributes {
			if strings.EqualFold(attribute.Name, attributePrivatePKCS8) &&
				(len(attribute.Values) != 0 || len(attribute.ByteValues) != 0) {
				t.Fatal("repository retained private readback buffers")
			}
		}
	}
}

func TestNewLDAPRepositoryRejectsTypedNilExecutor(t *testing.T) {
	var executor *fakeExecutor
	if _, err := NewLDAPRepository(executor); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewLDAPRepository() error = %v, want unavailable", err)
	}
}

func TestLDAPRepositoryRequiresExactNextStagingGenerationBeforeWrites(t *testing.T) {
	tests := []struct {
		name     string
		expected uint64
		number   uint64
		state    dkim2model.DatasetState
	}{
		{name: "skipped bootstrap", expected: 0, number: 2, state: dkim2model.DatasetStateStaging},
		{name: "skipped successor", expected: 1, number: 3, state: dkim2model.DatasetStateStaging},
		{name: "committed candidate", expected: 0, number: 1, state: dkim2model.DatasetStateCommitted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			repository := mustRepository(t, executor)
			candidate := testGeneration(t, test.number, test.state, "one.example")
			defer func() { _ = candidate.Close() }()
			if err := repository.Publish(context.Background(), test.expected, candidate); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Publish() error = %v, want malformed", err)
			}
			if len(executor.adds) != 0 || len(executor.modifies) != 0 || len(executor.searches) != 0 {
				t.Fatal("invalid generation performed LDAP I/O")
			}
		})
	}
}

func TestLDAPRepositoryRejectsStaleExpectedGenerationBeforeStaging(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	addCount := len(executor.adds)
	modifyCount := len(executor.modifies)
	stale := testGeneration(t, 3, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = stale.Close() }()
	if err := repository.Publish(context.Background(), 2, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("Publish() error = %v, want conflict", err)
	}
	if len(executor.adds) != addCount || len(executor.modifies) != modifyCount {
		t.Fatal("stale expected generation performed a write")
	}
}

func TestLDAPRepositoryBootstrapRejectsPointerAndOrphanConflicts(t *testing.T) {
	t.Run("existing current", func(t *testing.T) {
		executor := newFakeExecutor(testBaseDN)
		executor.put(metadataEntry("cn=current,"+testBaseDN, 7, datasetStateCommitted))
		repository := mustRepository(t, executor)
		candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
		defer func() { _ = candidate.Close() }()
		if err := repository.Publish(context.Background(), 0, candidate); !errors.Is(err, ErrConflict) {
			t.Fatalf("Publish() error = %v, want conflict", err)
		}
		if len(executor.adds) != 0 || len(executor.modifies) != 0 {
			t.Fatal("pointer conflict performed a write")
		}
	})

	t.Run("orphan generation", func(t *testing.T) {
		executor := newFakeExecutor(testBaseDN)
		executor.put(metadataEntry(
			attributeGeneration+"=9,ou=generations,"+testBaseDN, 9, datasetStateStaging,
		))
		repository := mustRepository(t, executor)
		candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
		defer func() { _ = candidate.Close() }()
		if err := repository.Publish(context.Background(), 0, candidate); !errors.Is(err, ErrConflict) {
			t.Fatalf("Publish() error = %v, want conflict", err)
		}
		if len(executor.adds) != 0 || len(executor.modifies) != 0 {
			t.Fatal("orphan conflict performed a write")
		}
	})
}

func TestLDAPRepositoryEveryStagingAddFailureLeavesPointerUnswitched(t *testing.T) {
	for failure := 1; failure <= 12; failure++ {
		t.Run(fmt.Sprintf("add-%d", failure), func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			executor.failAddAt = failure
			executor.addError = errors.New("private-key-marker")
			repository := mustRepository(t, executor)
			candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
			defer func() { _ = candidate.Close() }()
			err := repository.Publish(context.Background(), 0, candidate)
			if err == nil || strings.Contains(err.Error(), "private-key-marker") {
				t.Fatalf("Publish() returned unsafe error: %v", err)
			}
			if len(executor.modifies) != 0 {
				t.Fatal("partial stage reached a modify")
			}
		})
	}
}

func TestLDAPRepositoryReadbackMismatchAndReferralFailBeforeCommit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ldap.SearchResult)
	}{
		{
			name: "mismatch",
			mutate: func(result *ldap.SearchResult) {
				for _, entry := range result.Entries {
					if hasObjectClass(entry, classCredential) {
						setEntryAttribute(entry, attributeSelector, []string{"changed"})
						return
					}
				}
			},
		},
		{
			name: "referral",
			mutate: func(result *ldap.SearchResult) {
				result.Referrals = []string{"ldaps://referral.example/"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			executor.mutateGenerationRead = test.mutate
			repository := mustRepository(t, executor)
			candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
			defer func() { _ = candidate.Close() }()
			if err := repository.Publish(context.Background(), 0, candidate); err == nil {
				t.Fatal("Publish() accepted uncertain readback")
			}
			if len(executor.modifies) != 0 {
				t.Fatal("uncertain readback reached commit")
			}
		})
	}
}

func TestLDAPRepositoryCommitAndPointerFailuresNeverReportSuccess(t *testing.T) {
	for failure := 1; failure <= 2; failure++ {
		t.Run(fmt.Sprintf("modify-%d", failure), func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			executor.failModifyAt = failure
			if failure == 2 {
				executor.modifyError = ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("server-secret"))
			} else {
				executor.modifyError = errors.New("server-secret")
			}
			repository := mustRepository(t, executor)
			candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
			defer func() { _ = candidate.Close() }()
			err := repository.Publish(context.Background(), 0, candidate)
			if err == nil || strings.Contains(err.Error(), "server-secret") {
				t.Fatalf("Publish() returned unsafe error: %v", err)
			}
			if failure == 2 && !errors.Is(err, ErrConflict) {
				t.Fatalf("assertion failure = %v, want conflict", err)
			}
		})
	}
}

func TestLDAPRepositoryCancellationDuringReadbackStopsBeforeCommit(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	builder, err := first.NextBuilder(2, dkim2model.DatasetStateStaging)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	second, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	executor.mutateGenerationRead = func(*ldap.SearchResult) {
		reads++
		if reads == 2 {
			cancel()
		}
	}
	baselineModifies := len(executor.modifies)
	if err := repository.Publish(ctx, 1, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Publish() error = %v, want context cancellation", err)
	}
	if len(executor.modifies) != baselineModifies {
		t.Fatal("canceled staged readback reached generation commit")
	}
}

func TestLDAPRepositoryPreservesCompleteMultiDomainSuccessor(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	builder, err := current.NextBuilder(2, dkim2model.DatasetStateStaging)
	_ = current.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	second, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if err := repository.Publish(context.Background(), 1, second); err != nil {
		t.Fatalf("successor Publish() error = %v", err)
	}
	loaded, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	if loaded.Number() != 2 || len(loaded.Profiles()) != 2 {
		t.Fatal("successor lost unrelated domain records")
	}
	for _, domain := range []string{"one.example", "two.example"} {
		if _, found := loaded.ProfileByDomain(domain); !found {
			t.Fatalf("successor lost domain %q", domain)
		}
	}
}

func TestLDAPRepositoryRejectsMixedAndSurplusLDAPRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ldap.Entry)
	}{
		{
			name: "mixed generation",
			mutate: func(entry *ldap.Entry) {
				setEntryAttribute(entry, attributeGeneration, []string{"2"})
			},
		},
		{
			name: "surplus value",
			mutate: func(entry *ldap.Entry) {
				setEntryAttribute(entry, attributeGeneration, []string{"1", "1"})
			},
		},
		{
			name: "surplus attribute",
			mutate: func(entry *ldap.Entry) {
				entry.Attributes = append(entry.Attributes, ldap.NewEntryAttribute(attributeRollout, []string{"off"}))
			},
		},
		{
			name: "mixed class",
			mutate: func(entry *ldap.Entry) {
				setEntryAttribute(entry, attributeObjectClass, []string{classTop, classCredential, classPolicy})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			repository := mustRepository(t, executor)
			candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
			defer func() { _ = candidate.Close() }()
			if err := repository.Publish(context.Background(), 0, candidate); err != nil {
				t.Fatal(err)
			}
			for _, entry := range executor.entries {
				if hasObjectClass(entry, classCredential) {
					test.mutate(entry)
					break
				}
			}
			loaded, err := repository.LoadCurrent(context.Background())
			if loaded != nil {
				_ = loaded.Close()
			}
			if err == nil {
				t.Fatal("LoadCurrent() accepted malformed LDAP records")
			}
		})
	}
}

func TestLDAPRepositoryFixedDNAndFilterInputs(t *testing.T) {
	malicious := newFakeExecutor("ou=dkim2,not-a-dn")
	if _, err := NewLDAPRepository(malicious); err == nil {
		t.Fatal("NewLDAPRepository() accepted an injected base DN")
	}

	executor := newFakeExecutor(`ou=dkim2\,synthetic,dc=example,dc=org`)
	repository := mustRepository(t, executor)
	candidate := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = candidate.Close() }()
	if err := repository.Publish(context.Background(), 0, candidate); err != nil {
		t.Fatalf("Publish() with escaped configured base = %v", err)
	}
	for _, request := range executor.searches {
		if strings.Contains(request.Filter, "one.example") || strings.Contains(request.Filter, "selector") {
			t.Fatalf("request input reached LDAP filter: %q", request.Filter)
		}
	}
	for _, request := range executor.adds {
		if !isAtOrBelow(request.DN, executor.baseDN) {
			t.Fatalf("write escaped configured base: %q", request.DN)
		}
	}
}

func mustRepository(t *testing.T, executor *fakeExecutor) *LDAPRepository {
	t.Helper()
	repository, err := NewLDAPRepository(executor)
	if err != nil {
		t.Fatalf("NewLDAPRepository() error = %v", err)
	}
	return repository
}

func testGeneration(
	t *testing.T,
	number uint64,
	state dkim2model.DatasetState,
	domains ...string,
) *dkim2model.Generation {
	t.Helper()
	handles := make([]dkim2model.Handle, 0, len(domains))
	profiles := make([]dkim2model.Profile, 0, len(domains))
	credentials := make([]dkim2model.Credential, 0, len(domains))
	policies := make([]dkim2model.Policy, 0, len(domains))
	materials := make([]*dkim2model.KeyMaterial, 0, len(domains))
	defer func() {
		for _, material := range materials {
			_ = material.Close()
		}
	}()
	for index, domain := range domains {
		suffix := fmt.Sprintf("%d", index+1)
		pair, err := dkim2model.GenerateEd25519KeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := dkim2model.NewHandle(number, "handle-"+suffix)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := dkim2model.NewProfile(
			number, "profile-"+suffix, domain, dkim2model.RecordStatusDisabled,
			zeroTime(), zeroTime(),
		)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := dkim2model.NewCredential(
			number, profile.ID(), "selector-"+suffix,
			dkim2model.AlgorithmEd25519SHA256, pair.PublicSPKIDER(), handle.ID(),
		)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := dkim2model.NewPolicy(
			number, "tenant-"+suffix, domain, dkim2model.ProfileUseOriginator,
			profile.ID(), dkim2model.RecordStatusDisabled, dkim2model.RolloutOff,
			dkim2model.CompatibilityStrict, "",
		)
		if err != nil {
			t.Fatal(err)
		}
		material, err := dkim2model.NewKeyMaterial(
			number, policy.TenantID(), domain, policy.Use(), handle.ID(), pair,
		)
		_ = pair.Close()
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, handle)
		profiles = append(profiles, profile)
		credentials = append(credentials, credential)
		policies = append(policies, policy)
		materials = append(materials, material)
	}
	generation, err := dkim2model.NewGenerationWithState(
		number, state, handles, profiles, credentials, policies, materials,
	)
	if err != nil {
		t.Fatalf("NewGenerationWithState() error = %v", err)
	}
	return generation
}

func zeroTime() (result time.Time) { return result }

type fakeExecutor struct {
	baseDN               string
	entries              map[string]*ldap.Entry
	searches             []*ldap.SearchRequest
	adds                 []*ldap.AddRequest
	modifies             []*ldap.ModifyRequest
	failAddAt            int
	failModifyAt         int
	addError             error
	modifyError          error
	mutateGenerationRead func(*ldap.SearchResult)
	lastGenerationResult *ldap.SearchResult
}

func newFakeExecutor(baseDN string) *fakeExecutor {
	return &fakeExecutor{baseDN: baseDN, entries: make(map[string]*ldap.Entry)}
}

func (f *fakeExecutor) BaseDN() string { return f.baseDN }

func (f *fakeExecutor) SearchRequest(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches = append(f.searches, cloneSearchRequest(request))
	result := &ldap.SearchResult{}
	if request.Scope == ldap.ScopeBaseObject {
		entry := f.entries[dnKey(request.BaseDN)]
		if entry == nil {
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
		}
		result.Entries = []*ldap.Entry{cloneEntry(entry)}
		return result, nil
	}
	for _, entry := range f.entries {
		if request.Scope == ldap.ScopeSingleLevel && isDirectChild(entry.DN, request.BaseDN) ||
			request.Scope == ldap.ScopeWholeSubtree && isAtOrBelow(entry.DN, request.BaseDN) {
			result.Entries = append(result.Entries, cloneEntry(entry))
		}
	}
	if request.Scope == ldap.ScopeWholeSubtree && f.mutateGenerationRead != nil {
		f.mutateGenerationRead(result)
	}
	if request.Scope == ldap.ScopeWholeSubtree {
		f.lastGenerationResult = result
	}
	return result, nil
}

func (f *fakeExecutor) AddRequest(request *ldap.AddRequest) error {
	copyRequest := cloneAddRequest(request)
	f.adds = append(f.adds, copyRequest)
	if f.failAddAt > 0 && len(f.adds) == f.failAddAt {
		return f.addError
	}
	if _, duplicate := f.entries[dnKey(request.DN)]; duplicate {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("duplicate"))
	}
	attributes := make(map[string][]string, len(copyRequest.Attributes))
	for _, attribute := range copyRequest.Attributes {
		attributes[attribute.Type] = append([]string(nil), attribute.Vals...)
	}
	f.put(ldap.NewEntry(copyRequest.DN, attributes))
	return nil
}

func (f *fakeExecutor) ModifyRequest(request *ldap.ModifyRequest) (*ldap.ModifyResult, error) {
	copyRequest := cloneModifyRequest(request)
	f.modifies = append(f.modifies, copyRequest)
	if f.failModifyAt > 0 && len(f.modifies) == f.failModifyAt {
		return &ldap.ModifyResult{}, f.modifyError
	}
	entry := f.entries[dnKey(request.DN)]
	if entry == nil {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
	}
	for _, change := range copyRequest.Changes {
		if change.Operation != ldap.ReplaceAttribute {
			return nil, errors.New("unsupported fake change")
		}
		setEntryAttribute(entry, change.Modification.Type, change.Modification.Vals)
	}
	return &ldap.ModifyResult{}, nil
}

func (f *fakeExecutor) put(entry *ldap.Entry) { f.entries[dnKey(entry.DN)] = cloneEntry(entry) }

func metadataEntry(dn string, generation uint64, state string) *ldap.Entry {
	cn := "current"
	if strings.HasPrefix(dn, attributeGeneration+"=") {
		cn = "generation-" + fmt.Sprint(generation)
	}
	return ldap.NewEntry(dn, map[string][]string{
		attributeObjectClass:   {classTop, classDataset},
		attributeCN:            {cn},
		attributeSchemaVersion: {dkim2model.SchemaVersion},
		attributeGeneration:    {fmt.Sprint(generation)},
		attributeDatasetState:  {state},
	})
}

func cloneEntry(entry *ldap.Entry) *ldap.Entry {
	result := &ldap.Entry{DN: entry.DN, Attributes: make([]*ldap.EntryAttribute, 0, len(entry.Attributes))}
	for _, attribute := range entry.Attributes {
		cloned := &ldap.EntryAttribute{
			Name:       attribute.Name,
			Values:     append([]string(nil), attribute.Values...),
			ByteValues: make([][]byte, len(attribute.ByteValues)),
		}
		for index, value := range attribute.ByteValues {
			cloned.ByteValues[index] = append([]byte(nil), value...)
		}
		result.Attributes = append(result.Attributes, cloned)
	}
	return result
}

func cloneSearchRequest(request *ldap.SearchRequest) *ldap.SearchRequest {
	result := *request
	result.Attributes = append([]string(nil), request.Attributes...)
	result.Controls = append([]ldap.Control(nil), request.Controls...)
	return &result
}

func cloneAddRequest(request *ldap.AddRequest) *ldap.AddRequest {
	result := ldap.NewAddRequest(request.DN, append([]ldap.Control(nil), request.Controls...))
	for _, attribute := range request.Attributes {
		result.Attribute(attribute.Type, append([]string(nil), attribute.Vals...))
	}
	return result
}

func cloneModifyRequest(request *ldap.ModifyRequest) *ldap.ModifyRequest {
	result := ldap.NewModifyRequest(request.DN, append([]ldap.Control(nil), request.Controls...))
	result.Changes = append([]ldap.Change(nil), request.Changes...)
	for index := range result.Changes {
		result.Changes[index].Modification.Vals = append(
			[]string(nil), request.Changes[index].Modification.Vals...,
		)
	}
	return result
}

func dnKey(value string) string {
	parsed, err := ldap.ParseDN(value)
	if err != nil {
		return value
	}
	return strings.ToLower(parsed.String())
}

func isAtOrBelow(target, base string) bool {
	targetDN, targetErr := ldap.ParseDN(target)
	baseDN, baseErr := ldap.ParseDN(base)
	return targetErr == nil && baseErr == nil &&
		(baseDN.EqualFold(targetDN) || baseDN.AncestorOfFold(targetDN))
}

func isDirectChild(target, base string) bool {
	targetDN, targetErr := ldap.ParseDN(target)
	baseDN, baseErr := ldap.ParseDN(base)
	return targetErr == nil && baseErr == nil && baseDN.AncestorOfFold(targetDN) &&
		len(targetDN.RDNs) == len(baseDN.RDNs)+1
}

func hasObjectClass(entry *ldap.Entry, class string) bool {
	for _, value := range entry.GetEqualFoldAttributeValues(attributeObjectClass) {
		if value == class {
			return true
		}
	}
	return false
}

func setEntryAttribute(entry *ldap.Entry, name string, values []string) {
	for index, attribute := range entry.Attributes {
		if strings.EqualFold(attribute.Name, name) {
			entry.Attributes[index] = ldap.NewEntryAttribute(name, values)
			return
		}
	}
	entry.Attributes = append(entry.Attributes, ldap.NewEntryAttribute(name, values))
}
