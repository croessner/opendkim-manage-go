package dkim2store

import (
	"context"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
)

var _ GenerationRepository = (*LDAPRepository)(nil)

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
	pointer, absent, err := r.readCurrentPointer()
	if err != nil {
		return nil, err
	}
	if absent {
		empty, emptyErr := r.generationContainerEmpty()
		if emptyErr != nil || !empty {
			return nil, ErrMalformed
		}
		return nil, nil
	}

	entries, err := r.readGeneration(pointer.generation)
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

	second, secondAbsent, err := r.readCurrentPointer()
	if err != nil || secondAbsent || second != pointer {
		_ = generation.Close()
		return nil, ErrConflict
	}
	return generation, nil
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
		if err := r.prepareBootstrap(candidate.Number()); err != nil {
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

	if err := r.addCandidate(candidate); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	if err := r.validateReadback(candidate); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	if err := r.commitGeneration(candidate.Number()); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	return r.switchCurrent(expected, candidate.Number())
}

type currentPointer struct {
	schema     string
	generation uint64
	state      string
}

// readCurrentPointer loads one exact committed current fence or preserves proven absence.
func (r *LDAPRepository) readCurrentPointer() (currentPointer, bool, error) {
	request := boundedSearch(
		r.currentDN, ldap.ScopeBaseObject, 2,
		"("+attributeObjectClass+"="+ldap.EscapeFilter(classDataset)+")",
		[]string{attributeObjectClass, attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState},
	)
	result, err := r.executor.SearchRequest(request)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return currentPointer{}, true, nil
	}
	if err != nil || !exactSearchResult(result, 1) {
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
func (r *LDAPRepository) generationContainerEmpty() (bool, error) {
	result, err := r.executor.SearchRequest(boundedSearch(
		r.generationsBase, ldap.ScopeSingleLevel, 1,
		"("+attributeObjectClass+"=*)", []string{attributeObjectClass},
	))
	if err != nil || result == nil || len(result.Referrals) != 0 {
		return false, ErrUnavailable
	}
	return len(result.Entries) == 0, nil
}

// readGeneration retrieves one bounded complete subtree for exact mapping.
func (r *LDAPRepository) readGeneration(generation uint64) ([]*ldap.Entry, error) {
	// Organizational units do not carry dkim2Generation, so the structural read
	// intentionally uses objectClass only and validates every returned entry.
	result, err := r.executor.SearchRequest(boundedSearch(
		r.generationRoot(generation), ldap.ScopeWholeSubtree, maximumSearchEntries,
		"("+attributeObjectClass+"=*)", allAttributes,
	))
	if err != nil || result == nil || len(result.Referrals) != 0 ||
		len(result.Entries) < 6 || len(result.Entries) > maximumSearchEntries {
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
func (r *LDAPRepository) prepareBootstrap(generation uint64) error {
	_, absent, err := r.readCurrentPointer()
	if err != nil || !absent {
		return ErrConflict
	}
	empty, err := r.generationContainerEmpty()
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
	if err := r.executor.AddRequest(request); err != nil {
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
	return ErrUnavailable
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
