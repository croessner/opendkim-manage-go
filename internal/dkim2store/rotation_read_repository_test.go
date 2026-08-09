package dkim2store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

func TestNewRetainedHistoryWithLineageIsDetachedAndRedacted(t *testing.T) {
	generation := testGeneration(t, 1, dkim2model.DatasetStateCommitted, "one.example")
	defer func() {
		if err := generation.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	}()
	credential := generation.Credentials()[0]
	public := credential.PublicSPKIDER()
	fact, err := dkim2model.NewLineageFact(1, "20250701000000Z", "tenant-secret-marker", "one.example",
		dkim2model.ProfileUseOriginator, credential.Selector(), credential.Algorithm(), public, credential.HandleID())
	clear(public)
	if err != nil {
		t.Fatal(err)
	}
	input := dkim2model.LineageHistory{Complete: true, Facts: []dkim2model.LineageFact{fact}}
	history, err := NewRetainedHistoryWithLineage([]GenerationRoot{{Number: 1, State: dkim2model.DatasetStateCommitted}},
		[]string{credential.Selector()}, []string{credential.HandleID()}, input)
	if err != nil {
		t.Fatal(err)
	}
	input.Facts[0] = dkim2model.LineageFact{}
	cloned, err := history.LineageHistory()
	if err != nil || !cloned.Complete || len(cloned.Facts) != 1 {
		t.Fatalf("clone = %v, %v", cloned, err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, history); got != retainedHistoryRedacted || strings.Contains(got, "secret-marker") {
			t.Fatalf("format = %q", got)
		}
	}
	document, err := json.Marshal(history)
	if err != nil || string(document) != "{}" {
		t.Fatalf("JSON = %s, %v", document, err)
	}
}

func TestNewRetainedHistoryWithLineageRejectsIncompleteFacts(t *testing.T) {
	if _, err := NewRetainedHistoryWithLineage(nil, nil, nil, dkim2model.LineageHistory{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("incomplete lineage error = %v", err)
	}
}

func TestLDAPRepositoryReadHistoryAcceptsProvenEmptyContainer(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil {
		t.Fatalf("LoadRetainedHistory() error = %v", err)
	}
	if !history.Complete || len(history.Roots) != 0 {
		t.Fatal("empty generation container was not reported as complete empty history")
	}
}

func TestLDAPRepositoryReadHistoryAcceptsMateriallessBootstrapOnly(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	second := readSuccessorGeneration(t, first, 2)
	defer func() { _ = second.Close() }()
	if err := repository.Publish(context.Background(), 1, second); err != nil {
		t.Fatal(err)
	}

	legacyMaterialBase := removeHistoricalUnit(t, executor, "key-material", repository.generationRoot(1))
	setEntryAttribute(executor.entries[dnKey(repository.generationRoot(1))], attributeSchemaVersion, []string{legacySchemaVersion})
	executor.mutateSearch = func(request *ldap.SearchRequest, _ *ldap.SearchResult) error {
		if sameDN(request.BaseDN, legacyMaterialBase) {
			return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent legacy container"))
		}
		return nil
	}
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil || !history.Complete || len(history.Roots) != 2 {
		t.Fatalf("materialless bootstrap history = %v, %v", history, err)
	}
	credential := first.Credentials()[0]
	if used, usedErr := history.SelectorUsed(credential.Selector()); usedErr != nil || !used {
		t.Fatalf("bootstrap selector history = %v, %v", used, usedErr)
	}
	if used, usedErr := history.HandleUsed(credential.HandleID()); usedErr != nil || !used {
		t.Fatalf("bootstrap handle history = %v, %v", used, usedErr)
	}

	executor.mutateSearch = nil
	removeHistoricalUnit(t, executor, "key-material", repository.generationRoot(2))
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("materialless successor error = %v", err)
	}
}

func TestLDAPRepositoryReadHistoryRejectsLegacySchemaOutsideMateriallessBootstrap(t *testing.T) {
	for _, mode := range []string{"material", "successor"} {
		t.Run(mode, func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			repository := mustRepository(t, executor)
			first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
			defer func() { _ = first.Close() }()
			if err := repository.Publish(context.Background(), 0, first); err != nil {
				t.Fatal(err)
			}
			target := repository.generationRoot(1)
			if mode == "successor" {
				second := readSuccessorGeneration(t, first, 2)
				defer func() { _ = second.Close() }()
				if err := repository.Publish(context.Background(), 1, second); err != nil {
					t.Fatal(err)
				}
				target = repository.generationRoot(2)
			}
			setEntryAttribute(executor.entries[dnKey(target)], attributeSchemaVersion, []string{legacySchemaVersion})
			if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
				t.Fatalf("legacy %s history error = %v", mode, err)
			}
		})
	}
}

func removeHistoricalUnit(t *testing.T, executor *fakeExecutor, unit, root string) string {
	t.Helper()
	base := "ou=" + unit + "," + root
	for key, entry := range executor.entries {
		if isAtOrBelow(entry.DN, base) {
			delete(executor.entries, key)
		}
	}
	return base
}

func TestLDAPRepositoryReadHistoryAllowsIdenticalLineageAndRejectsConflictingReuse(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	second := readSuccessorGeneration(t, first, 2)
	defer func() { _ = second.Close() }()
	if err := repository.Publish(context.Background(), 1, second); err != nil {
		t.Fatal(err)
	}
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil {
		t.Fatalf("identical lineage across G1/G2 error = %v", err)
	}
	lineage, err := history.LineageHistory()
	if err != nil || len(lineage.Facts) != 2 {
		t.Fatalf("lineage facts = %d, %v", len(lineage.Facts), err)
	}

	for _, entry := range executor.entries {
		if strings.Contains(strings.ToLower(entry.DN), "dkim2generation=2") &&
			hasObjectClass(entry, classCredential) {
			setEntryAttribute(entry, attributeAlgorithm, []string{string(dkim2model.AlgorithmRSASHA256)})
			break
		}
	}
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("conflicting historical selector reuse error = %v", err)
	}
}

func TestLDAPRepositoryReadHistoryNeverRequestsHistoricalPrivateMaterial(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	searchStart := len(executor.searches)
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	for _, request := range executor.searches[searchStart:] {
		if request.Filter != "(objectClass=*)" && !sameDN(request.BaseDN, repository.generationRoot(1)) {
			t.Fatalf("history enumeration used class-hiding filter %q", request.Filter)
		}
		for _, attribute := range request.Attributes {
			if strings.EqualFold(attribute, attributePrivatePKCS8) || attribute == "*" || attribute == "+" {
				t.Fatalf("history requested forbidden attribute %q", attribute)
			}
		}
	}
}

func TestLDAPRepositoryReadHistoryRejectsUnusedProfileAndPolicy(t *testing.T) {
	for _, class := range []string{classProfile, classPolicy} {
		t.Run(class, func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			repository := mustRepository(t, executor)
			first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
			defer func() {
				if err := first.Close(); err != nil {
					t.Errorf("Close() = %v", err)
				}
			}()
			if err := repository.Publish(context.Background(), 0, first); err != nil {
				t.Fatal(err)
			}
			for _, entry := range executor.entries {
				if hasObjectClass(entry, class) && entry.GetAttributeValue(attributeCN) == "1" {
					extra := cloneEntry(entry)
					extra.DN = strings.Replace(extra.DN, "cn=1,", "cn=99,", 1)
					setEntryAttribute(extra, attributeCN, []string{"99"})
					if class == classProfile {
						setEntryAttribute(extra, attributeProfileID, []string{"profile-extra"})
					}
					if class == classPolicy {
						setEntryAttribute(extra, attributeTenantID, []string{"tenant-extra"})
					}
					executor.put(extra)
					break
				}
			}
			if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
				t.Fatalf("unused relationship error = %v", err)
			}
		})
	}
}

func TestLDAPRepositoryReadHistoryReportsOnlyFixedMalformedStage(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	for _, entry := range executor.entries {
		if hasObjectClass(entry, classCredential) {
			setEntryAttribute(entry, attributeHandleID, []string{"sensitive-marker"})
			break
		}
	}
	_, err := repository.LoadRetainedHistory(context.Background(), 8)
	if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "native-relationships is malformed") ||
		strings.Contains(err.Error(), "sensitive-marker") || strings.Contains(err.Error(), testBaseDN) {
		t.Fatalf("safe malformed history error = %q", err)
	}
}

func TestLDAPRepositoryReadHistoryReportsOnlyFixedUnavailableStage(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	executor.mutateSearch = func(request *ldap.SearchRequest, _ *ldap.SearchResult) error {
		if strings.HasPrefix(strings.ToLower(request.BaseDN), "ou=handles,") {
			return errors.New("sensitive-backend-marker")
		}
		return nil
	}
	_, err := repository.LoadRetainedHistory(context.Background(), 8)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "handles is unavailable") ||
		strings.Contains(err.Error(), "sensitive-backend-marker") || strings.Contains(err.Error(), testBaseDN) {
		t.Fatalf("safe unavailable history error = %q", err)
	}
}

func TestLDAPRepositoryReadHistoryRejectsUnknownDirectChild(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	}()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	executor.put(ldap.NewEntry("cn=99,ou=credentials,"+repository.generationRoot(1), map[string][]string{
		attributeObjectClass: {classTop, classPolicy}, attributeCN: {"99"},
	}))
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown child error = %v", err)
	}
}

func TestLDAPRepositoryReadHistoryRejectsNoncanonicalRecordSequences(t *testing.T) {
	for _, mode := range []string{"rdn", "gap", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			executor := newFakeExecutor(testBaseDN)
			repository := mustRepository(t, executor)
			first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
			defer func() {
				if err := first.Close(); err != nil {
					t.Errorf("Close() = %v", err)
				}
			}()
			if err := repository.Publish(context.Background(), 0, first); err != nil {
				t.Fatal(err)
			}
			for key, entry := range executor.entries {
				if !hasObjectClass(entry, classCredential) || entry.GetAttributeValue(attributeCN) != "1" {
					continue
				}
				switch mode {
				case "rdn":
					entry.DN = strings.Replace(entry.DN, "cn=1,", "cn=evil,", 1)
				case "gap":
					entry.DN = strings.Replace(entry.DN, "cn=1,", "cn=3,", 1)
					setEntryAttribute(entry, attributeCN, []string{"3"})
					delete(executor.entries, key)
					executor.entries[dnKey(entry.DN)] = entry
				case "duplicate":
					executor.entries["duplicate-record"] = cloneEntry(entry)
				}
				break
			}
			if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLDAPRepositoryReadHistoryRejectsDuplicateAlgorithmCardinality(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example", "two.example")
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	}()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	for _, entry := range executor.entries {
		if hasObjectClass(entry, classCredential) && entry.GetAttributeValue(attributeCN) == "2" {
			setEntryAttribute(entry, attributeProfileID, []string{"profile-1"})
			break
		}
	}
	if _, err := repository.LoadRetainedHistory(context.Background(), 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate profile algorithm error = %v", err)
	}
}

func TestLDAPRepositoryReadOperationalTimesUseExactCanonicalProjections(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	created, err := repository.LoadGenerationCreatedAt(context.Background(), 1)
	if err != nil || created.Format(generalizedTimeLayout) != "20250701000000Z" {
		t.Fatalf("created projection = %v, %v", created, err)
	}
	activation, err := repository.LoadCurrentActivation(context.Background())
	if err != nil || activation.Generation != 1 || activation.ModifiedAt.IsZero() {
		t.Fatalf("activation projection = %#v, %v", activation, err)
	}

	root := executor.entries[dnKey(repository.generationRoot(1))]
	setEntryAttribute(root, attributeCreateTimestamp, []string{"20250701000000.0Z"})
	if _, err := repository.LoadGenerationCreatedAt(context.Background(), 1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("fractional generalized time error = %v", err)
	}
	for _, request := range executor.searches {
		if sameDN(request.BaseDN, repository.generationRoot(1)) && len(request.Attributes) == 1 &&
			request.Attributes[0] == attributeCreateTimestamp {
			return
		}
	}
	t.Fatal("createTimestamp was not requested as a separate exact projection")
}

func TestLDAPRepositoryAutoLineageUsesCreateTimestampNotModifyTimestamp(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := fixedStoreGeneration(t, 1, dkim2model.DatasetStateStaging)
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}

	rootDN := repository.generationRoot(1)
	setEntryAttribute(executor.entries[dnKey(rootDN)], attributeModifyTimestamp, []string{"20300101000000Z"})
	searchStart := len(executor.searches)
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := history.LineageHistory()
	if err != nil {
		t.Fatal(err)
	}
	current, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = current.Close() }()
	decisions, err := dkim2model.EligibleBindings(
		time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC), current, lineage,
		dkim2model.RotationLimits{RotateAfter: 365 * 24 * time.Hour, MaximumClockSkew: 300 * time.Second,
			AllocationAttempts: 16, RSABits: dkim2model.DefaultRSABits, MaximumBindings: 10},
	)
	if err != nil || len(decisions) != 1 || !decisions[0].Due() {
		t.Fatalf("eligibility from immutable creation lineage = %v, %v", decisions, err)
	}

	foundCreateProjection := false
	for _, request := range executor.searches[searchStart:] {
		if !sameDN(request.BaseDN, rootDN) || len(request.Attributes) != 1 {
			continue
		}
		if request.Attributes[0] == attributeModifyTimestamp {
			t.Fatal("automatic lineage requested mutable modifyTimestamp")
		}
		if request.Attributes[0] == attributeCreateTimestamp {
			foundCreateProjection = true
		}
	}
	if !foundCreateProjection {
		t.Fatal("automatic lineage did not request immutable createTimestamp")
	}
}

func TestLDAPRepositoryReadRetainedGenerationRejectsStagingAndReturnsDetachedCommitted(t *testing.T) {
	executor := newFakeExecutor(testBaseDN)
	repository := mustRepository(t, executor)
	first := testGeneration(t, 1, dkim2model.DatasetStateStaging, "one.example")
	defer func() { _ = first.Close() }()
	if err := repository.Publish(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	retained, err := repository.LoadRetainedGeneration(context.Background(), 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Number() != 1 || retained.State() != dkim2model.DatasetStateCommitted {
		_ = retained.Close()
		t.Fatalf("retained generation = %v", retained)
	}
	_ = retained.Close()

	setEntryAttribute(executor.entries[dnKey(repository.generationRoot(1))], attributeDatasetState, []string{datasetStateStaging})
	if _, err := repository.LoadRetainedGeneration(context.Background(), 1, 8); !errors.Is(err, ErrMalformed) {
		t.Fatalf("staging retained generation error = %v", err)
	}
}

func TestParseGeneralizedTimeReadProjectionRejectsNonCanonicalForms(t *testing.T) {
	for _, value := range []string{"", "20250701000000.0Z", "20250701000000+0000", "20250230000000Z"} {
		if parsed, err := parseGeneralizedTime([]byte(value)); err == nil || !parsed.Equal(time.Time{}) {
			t.Fatalf("parseGeneralizedTime(%q) = %v, %v", value, parsed, err)
		}
	}
}

func readSuccessorGeneration(
	t *testing.T,
	current *dkim2model.Generation,
	number uint64,
) *dkim2model.Generation {
	t.Helper()
	builder, err := current.NextBuilder(number, dkim2model.DatasetStateStaging)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	candidate, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
