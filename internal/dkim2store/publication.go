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
	return r.addCandidateWithMetadata(ctx, candidate, nil)
}

// addCampaignCandidate creates one complete operation-bound v3 staging generation.
func (r *LDAPRepository) addCampaignCandidate(ctx context.Context, candidate *dkim2model.Generation, metadata dkim2model.CandidateMetadata) error {
	if metadata.ValidateCandidate(candidate) != nil {
		return ErrMalformed
	}
	return r.addCandidateWithMetadata(ctx, candidate, &metadata)
}

func (r *LDAPRepository) addCandidateWithMetadata(ctx context.Context, candidate *dkim2model.Generation, metadata *dkim2model.CandidateMetadata) error {
	generation := strconv.FormatUint(candidate.Number(), 10)
	v3 := metadata != nil
	rootDN := r.generationRoot(candidate.Number())
	rootAttributes := map[string][][]byte{
		attributeObjectClass:   bytesValues(classTop, classDataset),
		attributeCN:            bytesValues("generation-" + generation),
		attributeSchemaVersion: bytesValues(dkim2model.SchemaVersion),
		attributeGeneration:    bytesValues(generation),
		attributeDatasetState:  bytesValues(datasetStateStaging),
	}
	if metadata != nil {
		rootAttributes[attributeObjectClass] = bytesValues(classTop, classDataset, classAdministrativeMetadata)
		rootAttributes[attributeSchemaVersion] = bytesValues(dkim2model.SchemaVersionV3)
		rootAttributes[attributeSourceGeneration] = bytesValues(strconv.FormatUint(metadata.SourceGeneration(), 10))
		if err := metadata.WithLDAPValues(func(operation string, digest []byte) error {
			rootAttributes[attributeOperationID] = bytesValues(operation)
			rootAttributes[attributeCandidateDigest] = [][]byte{append([]byte(nil), digest...)}
			return nil
		}); err != nil {
			return ErrMalformed
		}
		defer clearAttributeMap(rootAttributes)
	}
	if err := r.addEntry(ctx, rootDN, rootAttributes); err != nil {
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
		if err := r.addEntry(ctx, r.recordDN(index, "handles", rootDN, v3), map[string][][]byte{
			attributeObjectClass: bytesValues(classTop, classHandle),
			attributeCN:          bytesValues(recordCNForSchema(index, v3)),
			attributeGeneration:  bytesValues(generation),
			attributeHandleID:    bytesValues(handle.ID()),
		}); err != nil {
			return err
		}
	}
	for index, profile := range candidate.Profiles() {
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classProfile),
			attributeCN:            bytesValues(recordCNForSchema(index, v3)),
			attributeGeneration:    bytesValues(generation),
			attributeProfileID:     bytesValues(profile.ID()),
			attributeSigningDomain: bytesValues(profile.SigningDomain()),
			attributeRecordStatus:  bytesValues(string(profile.Status())),
		}
		if notBefore, notAfter, present := profile.ValidityWindow(); present {
			attributes[attributeNotBefore] = bytesValues(notBefore.Format(time.RFC3339Nano))
			attributes[attributeNotAfter] = bytesValues(notAfter.Format(time.RFC3339Nano))
		}
		if err := r.addEntry(ctx, r.recordDN(index, "profiles", rootDN, v3), attributes); err != nil {
			return err
		}
	}
	for index, credential := range candidate.Credentials() {
		publicSPKI := credential.PublicSPKIDER()
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classCredential),
			attributeCN:            bytesValues(recordCNForSchema(index, v3)),
			attributeGeneration:    bytesValues(generation),
			attributeProfileID:     bytesValues(credential.ProfileID()),
			attributeAlgorithm:     bytesValues(string(credential.Algorithm())),
			attributeSelector:      bytesValues(credential.Selector()),
			attributePublicKeySPKI: {publicSPKI},
			attributeHandleID:      bytesValues(credential.HandleID()),
		}
		err := r.addEntry(ctx, r.recordDN(index, "credentials", rootDN, v3), attributes)
		clear(publicSPKI)
		if err != nil {
			return err
		}
	}
	for index, policy := range candidate.Policies() {
		attributes := map[string][][]byte{
			attributeObjectClass:   bytesValues(classTop, classPolicy),
			attributeCN:            bytesValues(recordCNForSchema(index, v3)),
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
		if err := r.addEntry(ctx, r.recordDN(index, "policies", rootDN, v3), attributes); err != nil {
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
			attributeCN:            bytesValues(recordCNForSchema(index, v3)),
			attributeGeneration:    bytesValues(generation),
			attributeTenantID:      bytesValues(material.TenantID()),
			attributeSigningDomain: bytesValues(material.SigningDomain()),
			attributeProfileUse:    bytesValues(string(material.Use())),
			attributeHandleID:      bytesValues(material.HandleID()),
			attributeAlgorithm:     bytesValues(string(material.Algorithm())),
			attributePublicKeySPKI: {publicSPKI},
			attributePrivatePKCS8:  {privatePKCS8},
		}
		err := r.addEntry(ctx, r.recordDN(index, "key-material", rootDN, v3), attributes)
		clear(publicSPKI)
		clear(privatePKCS8)
		if err != nil {
			return err
		}
	}
	return nil
}

// validateReadback tolerates bounded transiently incomplete LDAP views after
// successful adds, while every accepted result must still be complete and
// exactly equivalent to the candidate.
func (r *LDAPRepository) validateReadback(ctx context.Context, candidate *dkim2model.Generation) error {
	var err error
	for attempt := 0; attempt < r.limits.PublicationReadbackAttempts; attempt++ {
		if err = r.validateReadbackOnce(ctx, candidate); err == nil {
			return nil
		}
		if contextErr := validContext(ctx); contextErr != nil {
			return contextErr
		}
		if attempt+1 == r.limits.PublicationReadbackAttempts {
			break
		}
		timer := time.NewTimer(r.limits.PublicationReadbackInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (r *LDAPRepository) validateReadbackOnce(ctx context.Context, candidate *dkim2model.Generation) error {
	entries, err := r.readGeneration(ctx, candidate.Number())
	if err != nil {
		return err
	}
	actual, err := mapGeneration(
		entries, candidate.Number(), datasetStateStaging, r.generationRoot(candidate.Number()), r.limits,
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

// commitCampaignGeneration seals only the exact v3 candidate commitment.
func (r *LDAPRepository) commitCampaignGeneration(ctx context.Context, metadata dkim2model.CandidateMetadata) error {
	request := ldap.NewModifyRequest(r.generationRoot(metadata.Generation()), nil)
	request.Replace(attributeDatasetState, []string{datasetStateCommitted})
	assertion, err := campaignMetadataAssertion(metadata, datasetStateStaging)
	if err != nil {
		return ErrMalformed
	}
	control, err := newAssertionControl(assertion)
	if err != nil {
		return ErrMalformed
	}
	request.Controls = []ldap.Control{control}
	result, err := r.modify(ctx, request)
	if err != nil {
		return classifyWriteError(err)
	}
	if result == nil || result.Referral != "" {
		return ErrOutcomeUncertain
	}
	return nil
}

func campaignMetadataAssertion(metadata dkim2model.CandidateMetadata, state string) (string, error) {
	var operation string
	var digest []byte
	err := metadata.WithLDAPValues(func(value string, commitment []byte) error {
		operation, digest = value, append([]byte(nil), commitment...)
		return nil
	})
	defer clear(digest)
	if err != nil {
		return "", ErrMalformed
	}
	return "(&(objectClass=" + ldap.EscapeFilter(classDataset) + ")(" +
		attributeSchemaVersion + "=" + ldap.EscapeFilter(dkim2model.SchemaVersionV3) + ")(" +
		attributeGeneration + "=" + ldap.EscapeFilter(strconv.FormatUint(metadata.Generation(), 10)) + ")(" +
		attributeDatasetState + "=" + ldap.EscapeFilter(state) + ")(" +
		attributeOperationID + "=" + ldap.EscapeFilter(operation) + ")(" +
		attributeSourceGeneration + "=" + ldap.EscapeFilter(strconv.FormatUint(metadata.SourceGeneration(), 10)) + ")(" +
		attributeCandidateDigest + "=" + ldap.EscapeFilter(string(digest)) + "))", nil
}

func currentPointerAssertion(pointer currentPointer) string {
	filter := "(&(objectClass=" + ldap.EscapeFilter(classDataset) + ")(" +
		attributeSchemaVersion + "=" + ldap.EscapeFilter(pointer.schema) + ")(" +
		attributeGeneration + "=" + ldap.EscapeFilter(strconv.FormatUint(pointer.generation, 10)) + ")(" +
		attributeDatasetState + "=" + ldap.EscapeFilter(pointer.state) + ")"
	if pointer.schema == dkim2model.SchemaVersionV3 {
		filter += "(" + attributeCandidateDigest + "=" + ldap.EscapeFilter(string(pointer.digest[:])) + ")"
	}
	return filter + ")"
}

// markSourceWasActive persists monotonic source-generation activation evidence.
func (r *LDAPRepository) markSourceWasActive(ctx context.Context, source currentPointer) error {
	request := ldap.NewModifyRequest(r.generationRoot(source.generation), nil)
	request.Replace(attributeWasActive, []string{"TRUE"})
	control, err := newAssertionControl(currentPointerAssertion(source))
	if err != nil {
		return ErrMalformed
	}
	request.Controls = []ldap.Control{control}
	result, err := r.modify(ctx, request)
	if err != nil {
		return classifyWriteError(err)
	}
	if result == nil || result.Referral != "" {
		return ErrOutcomeUncertain
	}
	return nil
}

func (r *LDAPRepository) switchCurrentCampaign(ctx context.Context, source currentPointer, metadata dkim2model.CandidateMetadata) error {
	request := ldap.NewModifyRequest(r.currentDN, nil)
	if source.schema != dkim2model.SchemaVersionV3 {
		request.Add(attributeObjectClass, []string{classAdministrativeMetadata})
	}
	request.Replace(attributeSchemaVersion, []string{dkim2model.SchemaVersionV3})
	request.Replace(attributeGeneration, []string{strconv.FormatUint(metadata.Generation(), 10)})
	request.Replace(attributeDatasetState, []string{datasetStateCommitted})
	digest := metadata.DigestBytes()
	defer clear(digest)
	request.Replace(attributeCandidateDigest, []string{string(digest)})
	control, err := newAssertionControl(currentPointerAssertion(source))
	if err != nil {
		return ErrMalformed
	}
	request.Controls = []ldap.Control{control}
	result, err := r.modify(ctx, request)
	if err != nil {
		return classifyWriteError(err)
	}
	if result == nil || result.Referral != "" {
		return ErrOutcomeUncertain
	}
	pointer, absent, err := r.readCurrentPointer(ctx)
	if err != nil || absent || pointer.generation != metadata.Generation() || pointer.schema != dkim2model.SchemaVersionV3 ||
		pointer.digest != digestArray(metadata) {
		return ErrOutcomeUncertain
	}
	return nil
}

func digestArray(metadata dkim2model.CandidateMetadata) [dkim2model.CandidateDigestBytes]byte {
	var result [dkim2model.CandidateDigestBytes]byte
	value := metadata.DigestBytes()
	copy(result[:], value)
	clear(value)
	return result
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
func (r *LDAPRepository) recordDN(index int, unit, rootDN string, v3 bool) string {
	return attributeCN + "=" + ldap.EscapeDN(recordCNForSchema(index, v3)) + ",ou=" + ldap.EscapeDN(unit) + "," + rootDN
}

// recordCN derives the canonical DKIM2 storage sequence used by every provider.
func recordCN(index int) string { return "record-" + strconv.Itoa(index+1) }

// recordCNForSchema preserves legacy v2 storage while producing canonical v3 records.
func recordCNForSchema(index int, v3 bool) string {
	if v3 {
		return recordCN(index)
	}
	return strconv.Itoa(index + 1)
}
