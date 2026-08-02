package dkim2store

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
)

var errHistoryIncomplete = errors.New("DKIM2 retained history is incomplete")

const generalizedTimeLayout = "20060102150405Z"

var _ GenerationRepository = (*LDAPRepository)(nil)
var _ RotationReadRepository = (*LDAPRepository)(nil)
var _ RotationRepository = (*LDAPRepository)(nil)

// LDAPRepository owns the fixed DKIM2 dataset layout over an authenticated executor.
type LDAPRepository struct {
	executor        ldapstore.RequestExecutor
	baseDN          string
	currentDN       string
	generationsBase string
}

// NewLDAPRepository binds immutable generation operations to one validated LDAP base.
func NewLDAPRepository(executor ldapstore.RequestExecutor) (*LDAPRepository, error) {
	if executor == nil || isNilExecutor(executor) {
		return nil, ErrUnavailable
	}
	parsed, err := ldap.ParseDN(executor.BaseDN())
	if err != nil || len(parsed.RDNs) == 0 {
		return nil, ErrUnavailable
	}
	baseDN := parsed.String()
	return &LDAPRepository{
		executor:        executor,
		baseDN:          baseDN,
		currentDN:       "cn=current," + baseDN,
		generationsBase: "ou=generations," + baseDN,
	}, nil
}

// LoadCurrent returns one fully validated committed generation or nil for a proven empty backend.
func (r *LDAPRepository) LoadCurrent(ctx context.Context) (*dkim2model.Generation, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	pointer, absent, err := r.readCurrentPointer(ctx)
	if err != nil {
		return nil, err
	}
	if absent {
		empty, emptyErr := r.generationContainerEmpty(ctx)
		if emptyErr != nil || !empty {
			return nil, ErrMalformed
		}
		return nil, nil
	}

	entries, err := r.readGeneration(ctx, pointer.generation)
	if err != nil {
		return nil, err
	}
	generation, err := mapGeneration(entries, pointer.generation, datasetStateCommitted, r.generationRoot(pointer.generation))
	if err != nil {
		return nil, err
	}
	if err := validContext(ctx); err != nil {
		_ = generation.Close()
		return nil, err
	}

	second, secondAbsent, err := r.readCurrentPointer(ctx)
	if err != nil {
		_ = generation.Close()
		return nil, err
	}
	if secondAbsent || second != pointer {
		_ = generation.Close()
		return nil, ErrConflict
	}
	return generation, nil
}

// LoadGenerationCreatedAt returns only one canonical root creation timestamp.
func (r *LDAPRepository) LoadGenerationCreatedAt(ctx context.Context, generation uint64) (time.Time, error) {
	if err := validContext(ctx); err != nil {
		return time.Time{}, err
	}
	if r == nil || generation == 0 {
		return time.Time{}, ErrMalformed
	}
	created, err := r.loadOperationalTimestamp(ctx, r.generationRoot(generation), attributeCreateTimestamp)
	if err != nil {
		return time.Time{}, err
	}
	if err := validContext(ctx); err != nil {
		return time.Time{}, err
	}
	return created, nil
}

// LoadCurrentActivation atomically projects the exact pointer generation and modification time.
func (r *LDAPRepository) LoadCurrentActivation(ctx context.Context) (CurrentActivation, error) {
	if err := validContext(ctx); err != nil {
		return CurrentActivation{}, err
	}
	if r == nil {
		return CurrentActivation{}, ErrMalformed
	}
	request := boundedSearch(
		r.currentDN, ldap.ScopeBaseObject, 2,
		metadataAssertionFilter(datasetStateCommitted),
		[]string{attributeGeneration, attributeModifyTimestamp},
	)
	result, err := r.search(ctx, request)
	if err != nil || !exactSearchResult(result, 1) {
		if contextErr := validContext(ctx); contextErr != nil {
			return CurrentActivation{}, contextErr
		}
		return CurrentActivation{}, ErrUnavailable
	}
	values, err := exactProjectedEntry(result.Entries[0], r.currentDN,
		[]string{attributeGeneration, attributeModifyTimestamp})
	if err != nil {
		return CurrentActivation{}, err
	}
	generation, err := parseGeneration(values[attributeGeneration][0])
	if err != nil {
		return CurrentActivation{}, err
	}
	modified, err := parseGeneralizedTime(values[attributeModifyTimestamp][0])
	if err != nil {
		return CurrentActivation{}, err
	}
	if err := validContext(ctx); err != nil {
		return CurrentActivation{}, err
	}
	return CurrentActivation{Generation: generation, ModifiedAt: modified}, nil
}

func (r *LDAPRepository) loadOperationalTimestamp(ctx context.Context, dn, attribute string) (time.Time, error) {
	result, err := r.search(ctx, boundedSearch(
		dn, ldap.ScopeBaseObject, 2, metadataAssertionFilter(""), []string{attribute},
	))
	if err != nil || !exactSearchResult(result, 1) {
		if contextErr := validContext(ctx); contextErr != nil {
			return time.Time{}, contextErr
		}
		return time.Time{}, ErrUnavailable
	}
	values, err := exactProjectedEntry(result.Entries[0], dn, []string{attribute})
	if err != nil {
		return time.Time{}, err
	}
	return parseGeneralizedTime(values[attribute][0])
}

func metadataAssertionFilter(state string) string {
	filter := "(&(" + attributeObjectClass + "=" + ldap.EscapeFilter(classDataset) + ")(" +
		attributeSchemaVersion + "=" + ldap.EscapeFilter(dkim2model.SchemaVersion) + ")"
	if state != "" {
		filter += "(" + attributeDatasetState + "=" + ldap.EscapeFilter(state) + ")"
	}
	return filter + ")"
}

func exactProjectedEntry(entry *ldap.Entry, expectedDN string, attributes []string) (map[string][][]byte, error) {
	if entry == nil || !sameDN(entry.DN, expectedDN) || len(entry.Attributes) != len(attributes) {
		return nil, ErrMalformed
	}
	allowed := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		allowed[strings.ToLower(attribute)] = attribute
	}
	values := make(map[string][][]byte, len(attributes))
	for _, attribute := range entry.Attributes {
		name, found := allowed[strings.ToLower(attribute.Name)]
		if !found || len(attribute.ByteValues) != 1 {
			return nil, ErrMalformed
		}
		if _, duplicate := values[name]; duplicate || len(attribute.ByteValues[0]) > maximumAttributeBytes {
			return nil, ErrMalformed
		}
		values[name] = attribute.ByteValues
	}
	if len(values) != len(attributes) {
		return nil, ErrMalformed
	}
	return values, nil
}

func parseGeneralizedTime(value []byte) (time.Time, error) {
	if len(value) != len(generalizedTimeLayout) {
		return time.Time{}, ErrMalformed
	}
	parsed, err := time.Parse(generalizedTimeLayout, string(value))
	if err != nil || parsed.Location() != time.UTC || parsed.Format(generalizedTimeLayout) != string(value) {
		return time.Time{}, ErrMalformed
	}
	return parsed, nil
}

// LoadRetainedHistory reads every bounded generation root and only selector/handle projections.
func (r *LDAPRepository) LoadRetainedHistory(ctx context.Context, limit int) (RetainedHistory, error) {
	if err := validContext(ctx); err != nil {
		return RetainedHistory{}, err
	}
	if r == nil || limit < 2 || limit > 4096 {
		return RetainedHistory{}, ErrMalformed
	}
	result, err := r.search(ctx, boundedSearch(
		r.generationsBase, ldap.ScopeSingleLevel, limit,
		"("+attributeObjectClass+"=*)",
		[]string{attributeObjectClass, attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState},
	))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return NewRetainedHistory(nil, false, nil, nil), nil
	}
	if err != nil || result == nil || len(result.Referrals) != 0 {
		if contextErr := validContext(ctx); contextErr != nil {
			return RetainedHistory{}, contextErr
		}
		return RetainedHistory{}, ErrUnavailable
	}
	if len(result.Entries) >= limit {
		return NewRetainedHistory(nil, false, nil, nil), nil
	}
	history := NewRetainedHistory(nil, true, nil, nil)
	budget := workBudgetFromContext(ctx)
	seen := make(map[uint64]struct{}, len(result.Entries))
	for _, entry := range result.Entries {
		if err := validContext(ctx); err != nil {
			return RetainedHistory{}, err
		}
		if err := budget.consume(0, 0, 1); err != nil {
			return RetainedHistory{}, err
		}
		values, entryErr := exactEntry(entry, entry.DN, classDataset,
			[]string{attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState}, nil)
		if entryErr != nil {
			return RetainedHistory{}, ErrMalformed
		}
		if string(values[attributeSchemaVersion][0]) != dkim2model.SchemaVersion {
			return RetainedHistory{}, ErrMalformed
		}
		generation, parseErr := parseGeneration(values[attributeGeneration][0])
		state, stateErr := dkim2model.ParseDatasetState(string(values[attributeDatasetState][0]))
		if parseErr != nil || stateErr != nil || !sameDN(entry.DN, r.generationRoot(generation)) ||
			string(values[attributeCN][0]) != "generation-"+strconv.FormatUint(generation, 10) {
			return RetainedHistory{}, ErrMalformed
		}
		if _, duplicate := seen[generation]; duplicate {
			return RetainedHistory{}, ErrMalformed
		}
		seen[generation] = struct{}{}
		created, createdErr := r.loadOperationalTimestamp(ctx, r.generationRoot(generation), attributeCreateTimestamp)
		if createdErr != nil {
			return RetainedHistory{}, createdErr
		}
		history.Roots = append(history.Roots, GenerationRoot{Number: generation, State: state})
		if err := r.loadHistoricalLineages(ctx, &history, generation, created); err != nil {
			if errors.Is(err, errHistoryIncomplete) {
				return NewRetainedHistory(nil, false, nil, nil), nil
			}
			return RetainedHistory{}, err
		}
	}
	slices.SortFunc(history.Roots, func(left, right GenerationRoot) int {
		switch {
		case left.Number < right.Number:
			return -1
		case left.Number > right.Number:
			return 1
		default:
			return 0
		}
	})
	if len(history.Roots) != 0 && !contiguousGenerationRoots(history.Roots) {
		return RetainedHistory{}, ErrMalformed
	}
	if err := validContext(ctx); err != nil {
		return RetainedHistory{}, err
	}
	return history, nil
}

// LoadRetainedGeneration loads one exact committed immutable historical generation.
func (r *LDAPRepository) LoadRetainedGeneration(
	ctx context.Context,
	generation uint64,
	historyLimit int,
) (*dkim2model.Generation, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || generation == 0 {
		return nil, ErrMalformed
	}
	history, err := r.LoadRetainedHistory(ctx, historyLimit)
	if err != nil {
		return nil, err
	}
	if !history.Complete {
		return nil, ErrMalformed
	}
	state, found := retainedRootState(history.Roots, generation)
	if !found || state != dkim2model.DatasetStateCommitted {
		return nil, ErrMalformed
	}
	entries, err := r.readGeneration(ctx, generation)
	if err != nil {
		return nil, err
	}
	loaded, err := mapGeneration(entries, generation, datasetStateCommitted, r.generationRoot(generation))
	if err != nil {
		return nil, err
	}
	if err := validContext(ctx); err != nil {
		_ = loaded.Close()
		return nil, err
	}
	return loaded, nil
}

func retainedRootState(roots []GenerationRoot, generation uint64) (dkim2model.DatasetState, bool) {
	for _, root := range roots {
		if root.Number == generation {
			return root.State, true
		}
	}
	return "", false
}

// Stage writes and exactly reads back one unreachable strict successor.
func (r *LDAPRepository) Stage(
	ctx context.Context,
	candidate *dkim2model.Generation,
	historyLimit int,
) (*PreparedGeneration, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.executor == nil || candidate == nil || candidate.Number() < 2 ||
		candidate.State() != dkim2model.DatasetStateStaging {
		return nil, ErrMalformed
	}
	expected := candidate.Number() - 1
	owned, err := candidate.Clone()
	if err != nil {
		return nil, ErrMalformed
	}
	defer func() { _ = owned.Close() }()

	current, err := r.LoadCurrent(ctx)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, ErrConflict
	}
	currentNumber := current.Number()
	_ = current.Close()
	if currentNumber != expected {
		return nil, ErrConflict
	}
	history, err := r.LoadRetainedHistory(ctx, historyLimit)
	if err != nil {
		return nil, err
	}
	if !history.Complete || !historyHasExactCurrentMaximum(history.Roots, expected) {
		return nil, ErrConflict
	}
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	if err := r.addCandidate(ctx, owned); err != nil {
		return nil, err
	}
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	if err := r.validateReadback(ctx, owned); err != nil {
		return nil, err
	}
	return r.LoadPending(ctx, owned.Number(), historyLimit)
}

// LoadPending derives expected-current as candidate-1 and returns exact stored material.
func (r *LDAPRepository) LoadPending(
	ctx context.Context,
	candidateNumber uint64,
	historyLimit int,
) (*PreparedGeneration, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.executor == nil || candidateNumber < 2 {
		return nil, ErrMalformed
	}
	expected := candidateNumber - 1
	history, err := r.LoadRetainedHistory(ctx, historyLimit)
	if err != nil {
		return nil, err
	}
	if !history.Complete {
		return nil, ErrMalformed
	}
	state, found := retainedRootState(history.Roots, candidateNumber)
	if !found || (state != dkim2model.DatasetStateStaging && state != dkim2model.DatasetStateCommitted) ||
		!historyHasPendingShape(history.Roots, expected, candidateNumber) {
		return nil, ErrMalformed
	}
	pointer, absent, err := r.readCurrentPointer(ctx)
	if err != nil {
		return nil, err
	}
	if absent || (pointer.generation != expected && pointer.generation != candidateNumber) {
		return nil, ErrConflict
	}
	if pointer.generation == candidateNumber && state != dkim2model.DatasetStateCommitted {
		return nil, ErrMalformed
	}
	entries, err := r.readGeneration(ctx, candidateNumber)
	if err != nil {
		return nil, err
	}
	loaded, err := mapGeneration(entries, candidateNumber, string(state), r.generationRoot(candidateNumber))
	if err != nil {
		return nil, err
	}
	second, secondAbsent, err := r.readCurrentPointer(ctx)
	if err != nil || secondAbsent {
		_ = loaded.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrConflict
	}
	if second != pointer {
		_ = loaded.Close()
		return nil, ErrConflict
	}
	if err := validContext(ctx); err != nil {
		_ = loaded.Close()
		return nil, err
	}
	return newPreparedGeneration(expected, pointer.generation, loaded)
}

// CommitAndSwitch commits one exact staged candidate, then advances current once.
func (r *LDAPRepository) CommitAndSwitch(ctx context.Context, candidateNumber uint64, historyLimit int) error {
	prepared, err := r.LoadPending(ctx, candidateNumber, historyLimit)
	if err != nil {
		return err
	}
	defer func() { _ = prepared.Close() }()
	if prepared.ObservedCurrent() == candidateNumber {
		return nil
	}
	candidate, err := prepared.Generation()
	if err != nil {
		return err
	}
	state := candidate.State()
	_ = candidate.Close()
	if state == dkim2model.DatasetStateStaging {
		if err := validContext(ctx); err != nil {
			return err
		}
		if err := r.commitGeneration(ctx, candidateNumber); err != nil {
			return err
		}
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	committed, err := r.loadExactGeneration(ctx, candidateNumber, dkim2model.DatasetStateCommitted)
	if err != nil {
		return err
	}
	_ = committed.Close()
	pointer, absent, err := r.readCurrentPointer(ctx)
	if err != nil {
		return err
	}
	if absent || pointer.generation != prepared.ExpectedCurrent() {
		return ErrConflict
	}
	if err := r.switchCurrent(ctx, prepared.ExpectedCurrent(), candidateNumber); err != nil {
		return err
	}
	final, err := r.LoadPending(ctx, candidateNumber, historyLimit)
	if err != nil {
		return err
	}
	defer func() { _ = final.Close() }()
	if final.ObservedCurrent() != candidateNumber {
		return ErrConflict
	}
	return nil
}

func (r *LDAPRepository) loadExactGeneration(ctx context.Context, number uint64, state dkim2model.DatasetState) (*dkim2model.Generation, error) {
	entries, err := r.readGeneration(ctx, number)
	if err != nil {
		return nil, err
	}
	return mapGeneration(entries, number, string(state), r.generationRoot(number))
}

func historyHasExactCurrentMaximum(roots []GenerationRoot, current uint64) bool {
	if current == 0 || !contiguousGenerationRoots(roots) {
		return false
	}
	found := false
	for _, root := range roots {
		if root.Number > current || root.State != dkim2model.DatasetStateCommitted {
			return false
		}
		if root.Number == current {
			if root.State != dkim2model.DatasetStateCommitted || found {
				return false
			}
			found = true
		}
	}
	return found
}

func historyHasPendingShape(roots []GenerationRoot, expected, candidate uint64) bool {
	if candidate != expected+1 || !contiguousGenerationRoots(roots) {
		return false
	}
	expectedFound, candidateCount := false, 0
	for _, root := range roots {
		if root.Number > candidate {
			return false
		}
		if root.Number != candidate && root.State != dkim2model.DatasetStateCommitted {
			return false
		}
		if root.Number == expected && root.State == dkim2model.DatasetStateCommitted {
			expectedFound = true
		}
		if root.Number == candidate {
			candidateCount++
		}
	}
	return expectedFound && candidateCount == 1
}

// contiguousGenerationRoots requires every retained immutable root from one through the maximum.
func contiguousGenerationRoots(roots []GenerationRoot) bool {
	if len(roots) == 0 {
		return false
	}
	for index, root := range roots {
		if root.Number != uint64(index+1) {
			return false
		}
	}
	return true
}

type historicalProfile struct {
	id     string
	domain string
}

type historicalCredential struct {
	profileID string
	selector  string
	algorithm dkim2model.Algorithm
	public    []byte
	handle    string
}

type historicalPolicy struct {
	tenant    string
	domain    string
	use       dkim2model.ProfileUse
	profileID string
}

type historicalMaterial struct {
	tenant    string
	domain    string
	use       dkim2model.ProfileUse
	algorithm dkim2model.Algorithm
	public    []byte
	handle    string
}

// loadHistoricalLineages validates one complete public generation projection without private keys.
func (r *LDAPRepository) loadHistoricalLineages(ctx context.Context, history *RetainedHistory, generation uint64, created time.Time) error {
	root := r.generationRoot(generation)
	load := func(unit string, attributes []string, allowAbsent bool) ([]*ldap.Entry, error) {
		base := "ou=" + ldap.EscapeDN(unit) + "," + root
		result, err := r.search(ctx, boundedSearch(base, ldap.ScopeSingleLevel, maximumSearchEntries,
			"("+attributeObjectClass+"=*)", attributes))
		if allowAbsent && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) ||
			err == nil && result != nil && len(result.Referrals) == 0 && len(result.Entries) >= maximumSearchEntries {
			return nil, errHistoryIncomplete
		}
		if err != nil || result == nil || len(result.Referrals) != 0 {
			if contextErr := validContext(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, ErrUnavailable
		}
		for _, entry := range result.Entries {
			if entry == nil || !directChildDN(entry.DN, base) {
				return nil, ErrMalformed
			}
		}
		if !canonicalHistoricalRecordSet(result.Entries, base) {
			return nil, ErrMalformed
		}
		return result.Entries, nil
	}

	handles := make(map[string]struct{})
	handleEntries, err := load("handles",
		[]string{attributeObjectClass, attributeCN, attributeGeneration, attributeHandleID}, false)
	if err != nil {
		return err
	}
	for _, entry := range handleEntries {
		values, exactErr := exactEntry(entry, entry.DN, classHandle,
			[]string{attributeCN, attributeGeneration, attributeHandleID}, nil)
		if exactErr != nil {
			return ErrMalformed
		}
		handle := string(values[attributeHandleID][0])
		if exactGeneration(values[attributeGeneration][0], generation) != nil ||
			dkim2model.ValidateIdentifier(handle) != nil {
			return ErrMalformed
		}
		if _, duplicate := handles[handle]; duplicate {
			return ErrMalformed
		}
		handles[handle] = struct{}{}
	}

	profiles := make(map[string]historicalProfile)
	profileEntries, err := load("profiles", []string{
		attributeObjectClass, attributeCN, attributeGeneration, attributeProfileID, attributeSigningDomain,
	}, false)
	if err != nil {
		return err
	}
	for _, entry := range profileEntries {
		values, exactErr := exactEntry(entry, entry.DN, classProfile,
			[]string{attributeCN, attributeGeneration, attributeProfileID, attributeSigningDomain}, nil)
		if exactErr != nil {
			return ErrMalformed
		}
		profile := historicalProfile{id: string(values[attributeProfileID][0]), domain: string(values[attributeSigningDomain][0])}
		if exactGeneration(values[attributeGeneration][0], generation) != nil ||
			dkim2model.ValidateIdentifier(profile.id) != nil || dkim2model.ValidateCanonicalDNSName(profile.domain) != nil {
			return ErrMalformed
		}
		if _, duplicate := profiles[profile.id]; duplicate {
			return ErrMalformed
		}
		profiles[profile.id] = profile
	}

	policies := make(map[string]historicalPolicy)
	policyEntries, err := load("policies", []string{
		attributeObjectClass, attributeCN, attributeGeneration, attributeTenantID,
		attributeSigningDomain, attributeProfileUse, attributeProfileID,
	}, false)
	if err != nil {
		return err
	}
	for _, entry := range policyEntries {
		values, exactErr := exactEntry(entry, entry.DN, classPolicy, []string{
			attributeCN, attributeGeneration, attributeTenantID, attributeSigningDomain,
			attributeProfileUse, attributeProfileID,
		}, nil)
		if exactErr != nil {
			return ErrMalformed
		}
		use, useErr := dkim2model.ParseProfileUse(string(values[attributeProfileUse][0]))
		policy := historicalPolicy{tenant: string(values[attributeTenantID][0]), domain: string(values[attributeSigningDomain][0]),
			use: use, profileID: string(values[attributeProfileID][0])}
		profile, profileFound := profiles[policy.profileID]
		if exactGeneration(values[attributeGeneration][0], generation) != nil || useErr != nil ||
			dkim2model.ValidateIdentifier(policy.tenant) != nil || !use.SupportsNativeKeyCustody() ||
			dkim2model.ValidateCanonicalDNSName(policy.domain) != nil || !profileFound || profile.domain != policy.domain {
			return ErrMalformed
		}
		key := policy.tenant + "\x00" + policy.domain + "\x00" + string(policy.use)
		if _, duplicate := policies[key]; duplicate {
			return ErrMalformed
		}
		policies[key] = policy
	}

	credentials := make(map[string]historicalCredential)
	credentialEntries, err := load("credentials", []string{
		attributeObjectClass, attributeCN, attributeGeneration, attributeProfileID, attributeAlgorithm,
		attributeSelector, attributePublicKeySPKI, attributeHandleID,
	}, false)
	if err != nil {
		return err
	}
	selectorsInGeneration := make(map[string]struct{})
	profileAlgorithms := make(map[string]map[dkim2model.Algorithm]struct{})
	for _, entry := range credentialEntries {
		values, exactErr := exactEntry(entry, entry.DN, classCredential, []string{
			attributeCN, attributeGeneration, attributeProfileID, attributeAlgorithm,
			attributeSelector, attributePublicKeySPKI, attributeHandleID,
		}, nil)
		if exactErr != nil {
			return ErrMalformed
		}
		algorithm, algorithmErr := dkim2model.ParseAlgorithm(string(values[attributeAlgorithm][0]))
		credential := historicalCredential{profileID: string(values[attributeProfileID][0]), selector: string(values[attributeSelector][0]),
			algorithm: algorithm, public: append([]byte(nil), values[attributePublicKeySPKI][0]...), handle: string(values[attributeHandleID][0])}
		profile, profileFound := profiles[credential.profileID]
		if exactGeneration(values[attributeGeneration][0], generation) != nil || algorithmErr != nil ||
			!profileFound || dkim2model.ValidateDomainSelector(profile.domain, credential.selector) != nil ||
			dkim2model.ValidateIdentifier(credential.handle) != nil {
			return ErrMalformed
		}
		if _, err := dkim2model.NewCredential(generation, credential.profileID, credential.selector,
			credential.algorithm, credential.public, credential.handle); err != nil {
			return ErrMalformed
		}
		if _, duplicate := selectorsInGeneration[credential.selector]; duplicate {
			return ErrMalformed
		}
		if _, duplicate := credentials[credential.handle]; duplicate {
			return ErrMalformed
		}
		algorithms := profileAlgorithms[credential.profileID]
		if algorithms == nil {
			algorithms = make(map[dkim2model.Algorithm]struct{}, 2)
			profileAlgorithms[credential.profileID] = algorithms
		}
		if _, duplicate := algorithms[credential.algorithm]; duplicate {
			return ErrMalformed
		}
		algorithms[credential.algorithm] = struct{}{}
		selectorsInGeneration[credential.selector] = struct{}{}
		credentials[credential.handle] = credential
	}

	materials := make(map[string]historicalMaterial)
	bindingAlgorithms := make(map[string]struct{})
	materialEntries, err := load("key-material", []string{
		attributeObjectClass, attributeCN, attributeGeneration, attributeTenantID, attributeSigningDomain,
		attributeProfileUse, attributeHandleID, attributeAlgorithm, attributePublicKeySPKI,
	}, generation == 1)
	if err != nil {
		return err
	}
	for _, entry := range materialEntries {
		values, exactErr := exactEntry(entry, entry.DN, classKeyMaterial, []string{
			attributeCN, attributeGeneration, attributeTenantID, attributeSigningDomain,
			attributeProfileUse, attributeHandleID, attributeAlgorithm, attributePublicKeySPKI,
		}, nil)
		if exactErr != nil {
			return ErrMalformed
		}
		use, useErr := dkim2model.ParseProfileUse(string(values[attributeProfileUse][0]))
		algorithm, algorithmErr := dkim2model.ParseAlgorithm(string(values[attributeAlgorithm][0]))
		material := historicalMaterial{tenant: string(values[attributeTenantID][0]), domain: string(values[attributeSigningDomain][0]),
			use: use, algorithm: algorithm, public: append([]byte(nil), values[attributePublicKeySPKI][0]...),
			handle: string(values[attributeHandleID][0])}
		if exactGeneration(values[attributeGeneration][0], generation) != nil ||
			useErr != nil || algorithmErr != nil || dkim2model.ValidateIdentifier(material.tenant) != nil ||
			dkim2model.ValidateCanonicalDNSName(material.domain) != nil || !use.SupportsNativeKeyCustody() ||
			dkim2model.ValidateIdentifier(material.handle) != nil {
			return ErrMalformed
		}
		if _, duplicate := materials[material.handle]; duplicate {
			return ErrMalformed
		}
		selection := material.tenant + "\x00" + material.domain + "\x00" + string(material.use) + "\x00" + string(material.algorithm)
		if _, duplicate := bindingAlgorithms[selection]; duplicate {
			return ErrMalformed
		}
		bindingAlgorithms[selection] = struct{}{}
		materials[material.handle] = material
	}

	if len(handles) == 0 || len(handles) != len(credentials) || len(materials) != 0 && len(handles) != len(materials) {
		return ErrMalformed
	}
	usedProfiles := make(map[string]struct{}, len(profiles))
	usedPolicies := make(map[string]struct{}, len(policies))
	appendLineage := func(lineage publicLineage) error {
		for _, prior := range history.lineages {
			if (prior.selector == lineage.selector || prior.handle == lineage.handle) && !samePublicLineage(prior, lineage) {
				return ErrMalformed
			}
		}
		history.selectors[lineage.selector] = struct{}{}
		history.handles[lineage.handle] = struct{}{}
		history.lineages = append(history.lineages, lineage)
		return nil
	}
	if len(materials) == 0 {
		if generation != 1 {
			return ErrMalformed
		}
		policyByProfile := make(map[string]historicalPolicy, len(policies))
		for policyKey, policy := range policies {
			if _, duplicate := policyByProfile[policy.profileID]; duplicate {
				return ErrMalformed
			}
			policyByProfile[policy.profileID] = policy
			usedPolicies[policyKey] = struct{}{}
		}
		for handle := range handles {
			credential, credentialFound := credentials[handle]
			profile, profileFound := profiles[credential.profileID]
			policy, policyFound := policyByProfile[credential.profileID]
			if !credentialFound || !profileFound || !policyFound || profile.domain != policy.domain {
				return ErrMalformed
			}
			usedProfiles[credential.profileID] = struct{}{}
			if err := appendLineage(publicLineage{generation: generation, created: created.Format(generalizedTimeLayout),
				tenant: policy.tenant, domain: policy.domain, use: policy.use, profileID: credential.profileID,
				selector: credential.selector, algorithm: credential.algorithm,
				publicSPKI: append([]byte(nil), credential.public...), handle: handle}); err != nil {
				return err
			}
		}
		if len(usedProfiles) != len(profiles) || len(usedPolicies) != len(policies) {
			return ErrMalformed
		}
		return nil
	}
	for handle := range handles {
		credential, credentialFound := credentials[handle]
		material, materialFound := materials[handle]
		if !credentialFound || !materialFound || credential.algorithm != material.algorithm ||
			!bytes.Equal(credential.public, material.public) {
			return ErrMalformed
		}
		policyKey := material.tenant + "\x00" + material.domain + "\x00" + string(material.use)
		policy, policyFound := policies[policyKey]
		profile, profileFound := profiles[credential.profileID]
		if !policyFound || !profileFound || policy.profileID != credential.profileID || profile.domain != material.domain {
			return ErrMalformed
		}
		usedProfiles[credential.profileID] = struct{}{}
		usedPolicies[policyKey] = struct{}{}
		lineage := publicLineage{generation: generation, created: created.Format(generalizedTimeLayout),
			tenant: material.tenant, domain: material.domain, use: material.use, profileID: credential.profileID,
			selector: credential.selector, algorithm: credential.algorithm, publicSPKI: append([]byte(nil), credential.public...), handle: handle}
		if err := appendLineage(lineage); err != nil {
			return err
		}
	}
	if len(usedProfiles) != len(profiles) || len(usedPolicies) != len(policies) {
		return ErrMalformed
	}
	return nil
}

func directChildDN(child, parent string) bool {
	childDN, childErr := ldap.ParseDN(child)
	parentDN, parentErr := ldap.ParseDN(parent)
	if childErr != nil || parentErr != nil || len(childDN.RDNs) != len(parentDN.RDNs)+1 {
		return false
	}
	return (&ldap.DN{RDNs: childDN.RDNs[1:]}).EqualFold(parentDN)
}

func canonicalHistoricalRecordSet(entries []*ldap.Entry, base string) bool {
	seen := make(map[uint64]struct{}, len(entries))
	for _, entry := range entries {
		values, found := rawAttribute(entry, attributeCN)
		if !found || len(values) != 1 {
			return false
		}
		number, err := strconv.ParseUint(string(values[0]), 10, 64)
		if err != nil || number == 0 || strconv.FormatUint(number, 10) != string(values[0]) ||
			!sameDN(entry.DN, attributeCN+"="+ldap.EscapeDN(string(values[0]))+","+base) {
			return false
		}
		if _, duplicate := seen[number]; duplicate {
			return false
		}
		seen[number] = struct{}{}
	}
	for index := uint64(1); index <= uint64(len(entries)); index++ {
		if _, found := seen[index]; !found {
			return false
		}
	}
	return true
}

// Publish stages, validates, commits, and assertion-fences one complete next generation.
func (r *LDAPRepository) Publish(ctx context.Context, expected uint64, candidate *dkim2model.Generation) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if r == nil || r.executor == nil || candidate == nil || expected == ^uint64(0) ||
		candidate.Number() != expected+1 || candidate.State() != dkim2model.DatasetStateStaging {
		return ErrMalformed
	}
	owned, err := candidate.Clone()
	if err != nil {
		return ErrMalformed
	}
	defer func() { _ = owned.Close() }()
	candidate = owned

	if expected == 0 {
		if err := r.prepareBootstrap(ctx, candidate.Number()); err != nil {
			return err
		}
	} else {
		current, err := r.LoadCurrent(ctx)
		if err != nil {
			return err
		}
		if current == nil {
			return ErrConflict
		}
		currentNumber := current.Number()
		_ = current.Close()
		if currentNumber != expected {
			return ErrConflict
		}
	}

	if err := r.addCandidate(ctx, candidate); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	if err := r.validateReadback(ctx, candidate); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	if err := r.commitGeneration(ctx, candidate.Number()); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	return r.switchCurrent(ctx, expected, candidate.Number())
}

type currentPointer struct {
	schema     string
	generation uint64
	state      string
}

// readCurrentPointer loads one exact committed current fence or preserves proven absence.
func (r *LDAPRepository) readCurrentPointer(ctx context.Context) (currentPointer, bool, error) {
	request := boundedSearch(
		r.currentDN, ldap.ScopeBaseObject, 2,
		"("+attributeObjectClass+"="+ldap.EscapeFilter(classDataset)+")",
		[]string{attributeObjectClass, attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState},
	)
	result, err := r.search(ctx, request)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return currentPointer{}, true, nil
	}
	if err != nil || !exactSearchResult(result, 1) {
		if contextErr := validContext(ctx); contextErr != nil {
			return currentPointer{}, false, contextErr
		}
		return currentPointer{}, false, ErrUnavailable
	}
	values, err := exactEntry(
		result.Entries[0], r.currentDN, classDataset,
		[]string{attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState}, nil,
	)
	if err != nil || string(values[attributeCN][0]) != "current" ||
		string(values[attributeSchemaVersion][0]) != dkim2model.SchemaVersion ||
		string(values[attributeDatasetState][0]) != datasetStateCommitted {
		return currentPointer{}, false, ErrMalformed
	}
	generation, err := parseGeneration(values[attributeGeneration][0])
	if err != nil {
		return currentPointer{}, false, err
	}
	return currentPointer{
		schema: dkim2model.SchemaVersion, generation: generation, state: datasetStateCommitted,
	}, false, nil
}

// generationContainerEmpty proves that the fixed generation container exists without children.
func (r *LDAPRepository) generationContainerEmpty(ctx context.Context) (bool, error) {
	result, err := r.search(ctx, boundedSearch(
		r.generationsBase, ldap.ScopeSingleLevel, 1,
		"("+attributeObjectClass+"=*)", []string{attributeObjectClass},
	))
	if err != nil || result == nil || len(result.Referrals) != 0 {
		if contextErr := validContext(ctx); contextErr != nil {
			return false, contextErr
		}
		return false, ErrUnavailable
	}
	return len(result.Entries) == 0, nil
}

// readGeneration retrieves one bounded complete subtree for exact mapping.
func (r *LDAPRepository) readGeneration(ctx context.Context, generation uint64) ([]*ldap.Entry, error) {
	// Organizational units do not carry dkim2Generation, so the structural read
	// intentionally uses objectClass only and validates every returned entry.
	result, err := r.search(ctx, boundedSearch(
		r.generationRoot(generation), ldap.ScopeWholeSubtree, maximumSearchEntries,
		"("+attributeObjectClass+"=*)", allAttributes,
	))
	if err != nil || result == nil || len(result.Referrals) != 0 ||
		len(result.Entries) < 6 || len(result.Entries) > maximumSearchEntries {
		if contextErr := validContext(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, ErrUnavailable
	}
	return result.Entries, nil
}

// isNilExecutor rejects typed nil transports before invoking their methods.
func isNilExecutor(executor ldapstore.RequestExecutor) bool {
	value := reflect.ValueOf(executor)
	return (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) && value.IsNil()
}

// prepareBootstrap proves empty state and reserves cn=current as a staging fence.
func (r *LDAPRepository) prepareBootstrap(ctx context.Context, generation uint64) error {
	_, absent, err := r.readCurrentPointer(ctx)
	if err != nil || !absent {
		return ErrConflict
	}
	empty, err := r.generationContainerEmpty(ctx)
	if err != nil || !empty {
		return ErrConflict
	}
	request := newAdd(r.currentDN, map[string][][]byte{
		attributeObjectClass:   bytesValues(classTop, classDataset),
		attributeCN:            bytesValues("current"),
		attributeSchemaVersion: bytesValues(dkim2model.SchemaVersion),
		attributeGeneration:    bytesValues(strconv.FormatUint(generation, 10)),
		attributeDatasetState:  bytesValues(datasetStateStaging),
	})
	if err := r.add(ctx, request); err != nil {
		if contextErr := validContext(ctx); contextErr != nil {
			return contextErr
		}
		return classifyWriteError(err)
	}
	return nil
}

// generationRoot derives one fixed numeric generation subtree.
func (r *LDAPRepository) generationRoot(generation uint64) string {
	return attributeGeneration + "=" + strconv.FormatUint(generation, 10) + "," + r.generationsBase
}

// boundedSearch constructs one no-alias exact-attribute request with hard limits.
func boundedSearch(base string, scope, size int, filter string, attributes []string) *ldap.SearchRequest {
	request := ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases, size, searchTimeLimit,
		false, filter, attributes, nil,
	)
	request.EnforceSizeLimit = true
	return request
}

// exactSearchResult rejects referrals, nil entries, and cardinality ambiguity.
func exactSearchResult(result *ldap.SearchResult, entries int) bool {
	if result == nil || len(result.Referrals) != 0 || len(result.Entries) != entries {
		return false
	}
	for _, entry := range result.Entries {
		if entry == nil {
			return false
		}
	}
	return true
}

// validContext preserves cancellation without retaining request or backend details.
func validContext(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// search checks cancellation and cumulative work immediately around one LDAP search.
func (r *LDAPRepository) search(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	budget := workBudgetFromContext(ctx)
	if err := budget.consume(1, 0, 0); err != nil {
		return nil, err
	}
	result, err := r.executor.SearchRequest(request)
	if contextErr := validContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return result, err
	}
	bytesRead, sizeErr := ldapSearchResultBytes(result)
	if sizeErr != nil || budget.consume(0, bytesRead, 0) != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

// add checks cancellation and cumulative work immediately around one LDAP add.
func (r *LDAPRepository) add(ctx context.Context, request *ldap.AddRequest) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	budget := workBudgetFromContext(ctx)
	if err := budget.consume(1, ldapAddRequestBytes(request), 0); err != nil {
		return err
	}
	err := r.executor.AddRequest(request)
	if contextErr := validContext(ctx); contextErr != nil {
		return contextErr
	}
	return err
}

// modify checks cancellation and cumulative work immediately around one LDAP modify.
func (r *LDAPRepository) modify(ctx context.Context, request *ldap.ModifyRequest) (*ldap.ModifyResult, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	budget := workBudgetFromContext(ctx)
	if err := budget.consume(1, ldapModifyRequestBytes(request), 0); err != nil {
		return nil, err
	}
	result, err := r.executor.ModifyRequest(request)
	if contextErr := validContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	return result, err
}

// parseGeneration accepts one canonical nonzero full-range decimal generation.
func parseGeneration(value []byte) (uint64, error) {
	if len(value) == 0 || len(value) > 20 || len(value) > 1 && value[0] == '0' {
		return 0, ErrMalformed
	}
	generation, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != string(value) {
		return 0, ErrMalformed
	}
	return generation, nil
}

// classifyWriteError maps assertion failures to conflict and redacts all other diagnostics.
func classifyWriteError(err error) error {
	if err == nil {
		return nil
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return ErrConflict
	}
	return ErrOutcomeUncertain
}

// exactEntry validates one entry and returns borrowed projections so private values are not copied.
func exactEntry(
	entry *ldap.Entry,
	expectedDN string,
	class string,
	required []string,
	optional []string,
) (map[string][][]byte, error) {
	if entry == nil || !sameDN(entry.DN, expectedDN) {
		return nil, ErrMalformed
	}
	allowed := make(map[string]string, len(required)+len(optional)+1)
	allowed[strings.ToLower(attributeObjectClass)] = attributeObjectClass
	for _, name := range append(append([]string(nil), required...), optional...) {
		allowed[strings.ToLower(name)] = name
	}
	values := make(map[string][][]byte, len(entry.Attributes))
	success := false
	defer func() {
		if !success {
			clearAttributeMap(values)
		}
	}()
	total := 0
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			return nil, ErrMalformed
		}
		name, found := allowed[strings.ToLower(attribute.Name)]
		if !found {
			return nil, ErrMalformed
		}
		if _, duplicate := values[name]; duplicate || len(attribute.ByteValues) == 0 {
			return nil, ErrMalformed
		}
		projected := make([][]byte, len(attribute.ByteValues))
		for index, value := range attribute.ByteValues {
			if value == nil || len(value) > maximumAttributeBytes || total > maximumDatasetBytes-len(value) {
				return nil, ErrMalformed
			}
			total += len(value)
			projected[index] = value
		}
		values[name] = projected
	}
	for _, name := range append([]string{attributeObjectClass}, required...) {
		if len(values[name]) != 1 && name != attributeObjectClass {
			return nil, ErrMalformed
		}
		if _, found := values[name]; !found {
			return nil, ErrMalformed
		}
	}
	for _, name := range optional {
		if present := values[name]; len(present) > 1 {
			return nil, ErrMalformed
		}
	}
	if !exactStringSet(values[attributeObjectClass], []string{classTop, class}) {
		return nil, ErrMalformed
	}
	success = true
	return values, nil
}

// clearAttributeMap clears projected LDAP values on a rejected entry.
func clearAttributeMap(values map[string][][]byte) {
	for name, attributeValues := range values {
		for index := range attributeValues {
			clear(attributeValues[index])
			attributeValues[index] = nil
		}
		delete(values, name)
	}
}

// sameDN compares parsed LDAP names without string-format ambiguity.
func sameDN(left, right string) bool {
	leftDN, leftErr := ldap.ParseDN(left)
	rightDN, rightErr := ldap.ParseDN(right)
	return leftErr == nil && rightErr == nil && leftDN.EqualFold(rightDN)
}

// exactStringSet compares one small byte-valued LDAP set without aliases or surplus values.
func exactStringSet(actual [][]byte, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		seen[string(value)] = struct{}{}
	}
	if len(seen) != len(expected) {
		return false
	}
	for _, value := range expected {
		if _, found := seen[value]; !found {
			return false
		}
	}
	return true
}

// bytesValues converts fixed or already-validated strings into LDAP binary values.
func bytesValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = []byte(value)
	}
	return result
}

// newAdd builds one deterministic LDAP request while preserving binary DER values.
func newAdd(dn string, attributes map[string][][]byte) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	for _, name := range allAttributes {
		values := attributes[name]
		if len(values) == 0 {
			continue
		}
		textValues := make([]string, len(values))
		for index, value := range values {
			textValues[index] = string(value)
		}
		request.Attribute(name, textValues)
	}
	return request
}
