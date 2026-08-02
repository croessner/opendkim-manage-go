package dkim2store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// addCandidate creates one complete staging generation without editing committed data.
func (r *LDAPRepository) addCandidate(ctx context.Context, candidate *dkim2model.Generation) error {
	generation := strconv.FormatUint(candidate.Number(), 10)
	rootDN := r.generationRoot(candidate.Number())
	if err := r.addEntry(ctx, rootDN, map[string][][]byte{
		attributeObjectClass:   bytesValues(classTop, classDataset),
		attributeCN:            bytesValues("generation-" + generation),
		attributeSchemaVersion: bytesValues(dkim2model.SchemaVersion),
		attributeGeneration:    bytesValues(generation),
		attributeDatasetState:  bytesValues(datasetStateStaging),
	}); err != nil {
		return err
	}
	for _, unit := range generationUnits {
		if err := r.addEntry(ctx, "ou="+ldap.EscapeDN(unit)+","+rootDN, map[string][][]byte{
			attributeObjectClass: bytesValues(classTop, classOrganizationalUnit),
			attributeOU:          bytesValues(unit),
		}); err != nil {
			return err
		}
	}
	for index, handle := range candidate.Handles() {
		if err := r.addEntry(ctx, r.recordDN(index, "handles", rootDN), map[string][][]byte{
			attributeObjectClass: bytesValues(classTop, classHandle),
			attributeCN:          bytesValues(recordCN(index)),
			attributeGeneration:  bytesValues(generation),
			attributeHandleID:    bytesValues(handle.ID()),
		}); err != nil {
			return err
		}
	}
	for index, profile := range candidate.Profiles() {
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classProfile),
			attributeCN:            bytesValues(recordCN(index)),
			attributeGeneration:    bytesValues(generation),
			attributeProfileID:     bytesValues(profile.ID()),
			attributeSigningDomain: bytesValues(profile.SigningDomain()),
			attributeRecordStatus:  bytesValues(string(profile.Status())),
		}
		if notBefore, notAfter, present := profile.ValidityWindow(); present {
			attributes[attributeNotBefore] = bytesValues(notBefore.Format(time.RFC3339Nano))
			attributes[attributeNotAfter] = bytesValues(notAfter.Format(time.RFC3339Nano))
		}
		if err := r.addEntry(ctx, r.recordDN(index, "profiles", rootDN), attributes); err != nil {
			return err
		}
	}
	for index, credential := range candidate.Credentials() {
		publicSPKI := credential.PublicSPKIDER()
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classCredential),
			attributeCN:            bytesValues(recordCN(index)),
			attributeGeneration:    bytesValues(generation),
			attributeProfileID:     bytesValues(credential.ProfileID()),
			attributeAlgorithm:     bytesValues(string(credential.Algorithm())),
			attributeSelector:      bytesValues(credential.Selector()),
			attributePublicKeySPKI: {publicSPKI},
			attributeHandleID:      bytesValues(credential.HandleID()),
		}
		err := r.addEntry(ctx, r.recordDN(index, "credentials", rootDN), attributes)
		clear(publicSPKI)
		if err != nil {
			return err
		}
	}
	for index, policy := range candidate.Policies() {
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classPolicy),
			attributeCN:            bytesValues(recordCN(index)),
			attributeGeneration:    bytesValues(generation),
			attributeTenantID:      bytesValues(policy.TenantID()),
			attributeSigningDomain: bytesValues(policy.SigningDomain()),
			attributeProfileUse:    bytesValues(string(policy.Use())),
			attributeProfileID:     bytesValues(policy.ProfileID()),
			attributeRecordStatus:  bytesValues(string(policy.Status())),
			attributeRollout:       bytesValues(string(policy.Rollout())),
			attributeCompatibility: bytesValues(string(policy.Compatibility())),
		}
		if route := policy.FeedbackRouteID(); route != "" {
			attributes[attributeFeedbackRouteID] = bytesValues(route)
		}
		if err := r.addEntry(ctx, r.recordDN(index, "policies", rootDN), attributes); err != nil {
			return err
		}
	}
	materials := candidate.KeyMaterials()
	defer func() {
		for _, material := range materials {
			_ = material.Close()
		}
	}()
	for index, material := range materials {
		publicSPKI := material.PublicSPKIDER()
		privatePKCS8 := material.PrivatePKCS8DER()
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classKeyMaterial),
			attributeCN:            bytesValues(recordCN(index)),
			attributeGeneration:    bytesValues(generation),
			attributeTenantID:      bytesValues(material.TenantID()),
			attributeSigningDomain: bytesValues(material.SigningDomain()),
			attributeProfileUse:    bytesValues(string(material.Use())),
			attributeHandleID:      bytesValues(material.HandleID()),
			attributeAlgorithm:     bytesValues(string(material.Algorithm())),
			attributePublicKeySPKI: {publicSPKI},
			attributePrivatePKCS8:  {privatePKCS8},
		}
		err := r.addEntry(ctx, r.recordDN(index, "key-material", rootDN), attributes)
		clear(publicSPKI)
		clear(privatePKCS8)
		if err != nil {
			return err
		}
	}
	return nil
}

// validateReadback proves that staged LDAP data is valid and exactly equivalent to the candidate.
func (r *LDAPRepository) validateReadback(ctx context.Context, candidate *dkim2model.Generation) error {
	entries, err := r.readGeneration(ctx, candidate.Number())
	if err != nil {
		return err
	}
	actual, err := mapGeneration(
		entries, candidate.Number(), datasetStateStaging, r.generationRoot(candidate.Number()),
	)
	if err != nil {
		return err
	}
	defer func() { _ = actual.Close() }()
	if !candidate.Equivalent(actual) {
		return ErrMalformed
	}
	return nil
}

// commitGeneration changes only a fully read-back generation root to committed.
func (r *LDAPRepository) commitGeneration(ctx context.Context, generation uint64) error {
	request := ldap.NewModifyRequest(r.generationRoot(generation), nil)
	request.Replace(attributeDatasetState, []string{datasetStateCommitted})
	control, err := newAssertionControl(metadataAssertion(generation, datasetStateStaging))
	if err != nil {
		return ErrMalformed
	}
	request.Controls = []ldap.Control{control}
	result, err := r.modify(ctx, request)
	if err != nil {
		if contextErr := validContext(ctx); contextErr != nil {
			return contextErr
		}
		return classifyWriteError(err)
	}
	if result == nil || result.Referral != "" {
		return ErrOutcomeUncertain
	}
	return nil
}

// switchCurrent atomically claims the committed generation through RFC 4528.
func (r *LDAPRepository) switchCurrent(ctx context.Context, expected, generation uint64) error {
	var assertion string
	request := ldap.NewModifyRequest(r.currentDN, nil)
	if expected == 0 {
		assertion = metadataAssertion(generation, datasetStateStaging)
		request.Replace(attributeDatasetState, []string{datasetStateCommitted})
	} else {
		assertion = metadataAssertion(expected, datasetStateCommitted)
		request.Replace(attributeGeneration, []string{strconv.FormatUint(generation, 10)})
	}
	control, err := newAssertionControl(assertion)
	if err != nil {
		return ErrMalformed
	}
	request.Controls = []ldap.Control{control}
	result, err := r.modify(ctx, request)
	if err != nil {
		if contextErr := validContext(ctx); contextErr != nil {
			return contextErr
		}
		classified := classifyWriteError(err)
		if !errors.Is(classified, ErrOutcomeUncertain) {
			return classified
		}
		pointer, absent, readErr := r.readCurrentPointer(ctx)
		if readErr != nil || absent {
			return ErrOutcomeUncertain
		}
		if pointer.generation == generation {
			return nil
		}
		if pointer.generation == expected {
			return ErrOutcomeUncertain
		}
		return ErrConflict
	}
	if result == nil || result.Referral != "" {
		pointer, absent, readErr := r.readCurrentPointer(ctx)
		if readErr != nil || absent {
			return ErrOutcomeUncertain
		}
		if pointer.generation == generation {
			return nil
		}
		if pointer.generation == expected {
			return ErrOutcomeUncertain
		}
		return ErrConflict
	}
	pointer, absent, err := r.readCurrentPointer(ctx)
	if err != nil || absent || pointer.generation != generation {
		return ErrConflict
	}
	return nil
}

// metadataAssertion builds one exact schema, generation, and state fence.
func metadataAssertion(generation uint64, state string) string {
	return "(&(" + attributeSchemaVersion + "=" + ldap.EscapeFilter(dkim2model.SchemaVersion) + ")(" +
		attributeGeneration + "=" + ldap.EscapeFilter(strconv.FormatUint(generation, 10)) + ")(" +
		attributeDatasetState + "=" + ldap.EscapeFilter(state) + "))"
}

// newAssertionControl compiles one critical RFC 4528 assertion filter.
func newAssertionControl(filter string) (ldap.Control, error) {
	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, err
	}
	return ldap.NewControlString(assertionControlOID, true, string(compiled.Bytes())), nil
}

// addEntry performs one complete immutable add and releases request-owned values afterward.
func (r *LDAPRepository) addEntry(ctx context.Context, dn string, attributes map[string][][]byte) error {
	request := newAdd(dn, attributes)
	err := r.add(ctx, request)
	for attributeIndex := range request.Attributes {
		for valueIndex := range request.Attributes[attributeIndex].Vals {
			request.Attributes[attributeIndex].Vals[valueIndex] = ""
		}
		request.Attributes[attributeIndex].Vals = nil
	}
	if err != nil {
		if contextErr := validContext(ctx); contextErr != nil {
			return contextErr
		}
		return classifyWriteError(err)
	}
	return nil
}

// recordDN derives one storage-only sequence RDN beneath a fixed unit.
func (r *LDAPRepository) recordDN(index int, unit, rootDN string) string {
	return attributeCN + "=" + ldap.EscapeDN(recordCN(index)) + ",ou=" + ldap.EscapeDN(unit) + "," + rootDN
}

// recordCN derives one canonical positive storage sequence.
func recordCN(index int) string { return strconv.Itoa(index + 1) }
