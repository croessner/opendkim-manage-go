package dkim2store

import (
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// mapGeneration validates one exact closed LDAP subtree through the domain model.
func mapGeneration(
	entries []*ldap.Entry,
	generation uint64,
	state string,
	rootDN string,
	limits Limits,
) (*dkim2model.Generation, error) {
	if generation == 0 || limits.Validate() != nil || len(entries) < 6 || len(entries) > limits.MaxGenerationEntries {
		return nil, ErrMalformed
	}
	defer clearSensitiveEntries(entries)
	if validateDatasetSize(entries, limits) != nil {
		return nil, ErrMalformed
	}
	parsedState, err := dkim2model.ParseDatasetState(state)
	if err != nil {
		return nil, ErrMalformed
	}

	var handles []dkim2model.Handle
	var profiles []dkim2model.Profile
	var credentials []dkim2model.Credential
	var policies []dkim2model.Policy
	var materials []*dkim2model.KeyMaterial
	defer func() {
		for _, material := range materials {
			_ = material.Close()
		}
	}()

	rootSeen := false
	rootSchema := ""
	var rootMetadata dkim2model.CandidateMetadata
	units := make(map[string]struct{}, len(generationUnits))
	storageDNs := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry == nil {
			return nil, ErrMalformed
		}
		parsedDN, parseErr := ldap.ParseDN(entry.DN)
		if parseErr != nil {
			return nil, ErrMalformed
		}
		dnKey := strings.ToLower(parsedDN.String())
		if _, duplicate := storageDNs[dnKey]; duplicate {
			return nil, ErrMalformed
		}
		storageDNs[dnKey] = struct{}{}

		class, classErr := structuralClass(entry)
		if classErr != nil {
			return nil, classErr
		}
		switch class {
		case classDataset:
			if rootSeen || !sameDN(entry.DN, rootDN) {
				return nil, ErrMalformed
			}
			schemaValues, schemaFound := rawAttribute(entry, attributeSchemaVersion)
			if !schemaFound || len(schemaValues) != 1 {
				return nil, ErrMalformed
			}
			rootSchema = string(schemaValues[0])
			required := []string{attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState}
			optional := []string{attributeWasActive}
			if rootSchema == dkim2model.SchemaVersionV3 {
				required = append(required, attributeCandidateDigest, attributeOperationID, attributeSourceGeneration)
			}
			values, exactErr := exactEntry(entry, rootDN, classDataset, required, optional, limits)
			if exactErr != nil || string(values[attributeCN][0]) != "generation-"+strconv.FormatUint(generation, 10) ||
				(rootSchema != dkim2model.SchemaVersion && rootSchema != dkim2model.SchemaVersionV3) ||
				string(values[attributeDatasetState][0]) != state ||
				exactGeneration(values[attributeGeneration][0], generation) != nil {
				return nil, ErrMalformed
			}
			if rootSchema == dkim2model.SchemaVersionV3 {
				source, parseErr := parseGeneration(values[attributeSourceGeneration][0])
				if parseErr != nil {
					return nil, ErrMalformed
				}
				rootMetadata, parseErr = dkim2model.ParseCandidateMetadata(
					string(values[attributeOperationID][0]), source, generation, values[attributeCandidateDigest][0],
				)
				if parseErr != nil {
					return nil, ErrMalformed
				}
			}
			rootSeen = true
		case classOrganizationalUnit:
			unit, unitErr := exactUnit(entry, rootDN, limits)
			if unitErr != nil {
				return nil, unitErr
			}
			if _, duplicate := units[unit]; duplicate {
				return nil, ErrMalformed
			}
			units[unit] = struct{}{}
		case classHandle:
			values, exactErr := exactRecord(entry, rootDN, "handles", classHandle, []string{
				attributeGeneration, attributeHandleID,
			}, nil, limits)
			if exactErr != nil || exactGeneration(values[attributeGeneration][0], generation) != nil {
				return nil, ErrMalformed
			}
			handle, modelErr := dkim2model.NewHandle(generation, string(values[attributeHandleID][0]))
			if modelErr != nil {
				return nil, ErrMalformed
			}
			handles = append(handles, handle)
		case classProfile:
			values, exactErr := exactRecord(entry, rootDN, "profiles", classProfile, []string{
				attributeGeneration, attributeProfileID, attributeSigningDomain, attributeRecordStatus,
			}, []string{attributeNotBefore, attributeNotAfter}, limits)
			if exactErr != nil || exactGeneration(values[attributeGeneration][0], generation) != nil {
				return nil, ErrMalformed
			}
			status, modelErr := dkim2model.ParseRecordStatus(string(values[attributeRecordStatus][0]))
			if modelErr != nil {
				return nil, ErrMalformed
			}
			notBefore, notAfter, timeErr := parseValidity(values)
			if timeErr != nil {
				return nil, timeErr
			}
			profile, modelErr := dkim2model.NewProfile(
				generation, string(values[attributeProfileID][0]),
				string(values[attributeSigningDomain][0]), status, notBefore, notAfter,
			)
			if modelErr != nil {
				return nil, ErrMalformed
			}
			profiles = append(profiles, profile)
		case classCredential:
			values, exactErr := exactRecord(entry, rootDN, "credentials", classCredential, []string{
				attributeGeneration, attributeProfileID, attributeAlgorithm, attributeSelector,
				attributePublicKeySPKI, attributeHandleID,
			}, nil, limits)
			if exactErr != nil || exactGeneration(values[attributeGeneration][0], generation) != nil {
				return nil, ErrMalformed
			}
			algorithm, modelErr := dkim2model.ParseAlgorithm(string(values[attributeAlgorithm][0]))
			if modelErr != nil {
				return nil, ErrMalformed
			}
			credential, modelErr := dkim2model.NewCredential(
				generation, string(values[attributeProfileID][0]), string(values[attributeSelector][0]),
				algorithm, values[attributePublicKeySPKI][0], string(values[attributeHandleID][0]),
			)
			if modelErr != nil {
				return nil, ErrMalformed
			}
			credentials = append(credentials, credential)
		case classPolicy:
			values, exactErr := exactRecord(entry, rootDN, "policies", classPolicy, []string{
				attributeGeneration, attributeTenantID, attributeSigningDomain,
				attributeProfileUse, attributeProfileID, attributeRecordStatus,
				attributeRollout, attributeCompatibility,
			}, []string{attributeFeedbackRouteID}, limits)
			if exactErr != nil || exactGeneration(values[attributeGeneration][0], generation) != nil {
				return nil, ErrMalformed
			}
			policy, modelErr := mapPolicy(generation, values)
			if modelErr != nil {
				return nil, ErrMalformed
			}
			policies = append(policies, policy)
		case classKeyMaterial:
			values, exactErr := exactRecord(entry, rootDN, "key-material", classKeyMaterial, []string{
				attributeGeneration, attributeTenantID, attributeSigningDomain, attributeProfileUse,
				attributeHandleID, attributeAlgorithm, attributePublicKeySPKI, attributePrivatePKCS8,
			}, nil, limits)
			if exactErr != nil {
				return nil, ErrMalformed
			}
			if exactGeneration(values[attributeGeneration][0], generation) != nil {
				clearAttributeMap(values)
				return nil, ErrMalformed
			}
			material, modelErr := mapKeyMaterial(generation, values)
			clearAttributeMap(values)
			if modelErr != nil {
				return nil, ErrMalformed
			}
			materials = append(materials, material)
		default:
			return nil, ErrMalformed
		}
	}
	if !rootSeen || len(units) != len(generationUnits) {
		return nil, ErrMalformed
	}
	result, err := dkim2model.NewGenerationWithState(
		generation, parsedState, handles, profiles, credentials, policies, materials,
	)
	if err != nil {
		return nil, ErrMalformed
	}
	if rootSchema == dkim2model.SchemaVersionV3 && rootMetadata.ValidateCandidate(result) != nil {
		_ = result.Close()
		return nil, ErrMalformed
	}
	return result, nil
}

// projectCampaignMetadata copies only non-key v3 root evidence before full mapping clears LDAP buffers.
func projectCampaignMetadata(entries []*ldap.Entry, rootDN string, generation uint64, limits Limits) (dkim2model.CandidateMetadata, bool, error) {
	for _, entry := range entries {
		if entry == nil || !sameDN(entry.DN, rootDN) {
			continue
		}
		schema, found := rawAttribute(entry, attributeSchemaVersion)
		if !found || len(schema) != 1 {
			return dkim2model.CandidateMetadata{}, false, ErrMalformed
		}
		if string(schema[0]) != dkim2model.SchemaVersionV3 {
			return dkim2model.CandidateMetadata{}, false, nil
		}
		values, err := exactEntry(entry, rootDN, classDataset,
			[]string{attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState,
				attributeCandidateDigest, attributeOperationID, attributeSourceGeneration},
			[]string{attributeWasActive}, limits)
		if err != nil {
			return dkim2model.CandidateMetadata{}, false, ErrMalformed
		}
		source, err := parseGeneration(values[attributeSourceGeneration][0])
		if err != nil {
			return dkim2model.CandidateMetadata{}, false, ErrMalformed
		}
		metadata, err := dkim2model.ParseCandidateMetadata(
			string(values[attributeOperationID][0]), source, generation,
			append([]byte(nil), values[attributeCandidateDigest][0]...),
		)
		if err != nil {
			return dkim2model.CandidateMetadata{}, false, ErrMalformed
		}
		return metadata, true, nil
	}
	return dkim2model.CandidateMetadata{}, false, ErrMalformed
}

// structuralClass accepts one known structural class and the sole v3 root auxiliary class.
func structuralClass(entry *ldap.Entry) (string, error) {
	values, found := rawAttribute(entry, attributeObjectClass)
	if !found {
		return "", ErrMalformed
	}
	for _, class := range []string{
		classDataset, classOrganizationalUnit, classHandle, classProfile,
		classCredential, classPolicy, classKeyMaterial,
	} {
		if exactStringSet(values, []string{classTop, class}) {
			return class, nil
		}
	}
	if exactStringSet(values, []string{classTop, classDataset, classAdministrativeMetadata}) {
		return classDataset, nil
	}
	return "", ErrMalformed
}

// exactUnit validates one of the five fixed organizational units.
func exactUnit(entry *ldap.Entry, rootDN string, limits Limits) (string, error) {
	for _, unit := range generationUnits {
		dn := "ou=" + ldap.EscapeDN(unit) + "," + rootDN
		if !sameDN(entry.DN, dn) {
			continue
		}
		values, err := exactEntry(entry, dn, classOrganizationalUnit, []string{attributeOU}, nil, limits)
		if err != nil || string(values[attributeOU][0]) != unit {
			return "", ErrMalformed
		}
		return unit, nil
	}
	return "", ErrMalformed
}

// exactRecord validates one canonical positive storage RDN under its fixed unit.
func exactRecord(
	entry *ldap.Entry,
	rootDN string,
	unit string,
	class string,
	required []string,
	optional []string,
	limits Limits,
) (map[string][][]byte, error) {
	cnValues, found := rawAttribute(entry, attributeCN)
	if !found || len(cnValues) != 1 {
		return nil, ErrMalformed
	}
	cn := string(cnValues[0])
	parsed, err := strconv.ParseUint(cn, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != cn {
		return nil, ErrMalformed
	}
	dn := attributeCN + "=" + ldap.EscapeDN(cn) + ",ou=" + ldap.EscapeDN(unit) + "," + rootDN
	return exactEntry(entry, dn, class, append([]string{attributeCN}, required...), optional, limits)
}

// rawAttribute returns one unique case-insensitive raw attribute projection.
func rawAttribute(entry *ldap.Entry, name string) ([][]byte, bool) {
	if entry == nil {
		return nil, false
	}
	var found [][]byte
	for _, attribute := range entry.Attributes {
		if attribute != nil && strings.EqualFold(attribute.Name, name) {
			if found != nil {
				return nil, false
			}
			found = attribute.ByteValues
		}
	}
	return found, found != nil
}

// exactGeneration proves one record belongs only to the expected generation.
func exactGeneration(value []byte, expected uint64) error {
	generation, err := parseGeneration(value)
	if err != nil || generation != expected {
		return ErrMalformed
	}
	return nil
}

// parseValidity requires both or neither canonical UTC RFC3339Nano bounds.
func parseValidity(values map[string][][]byte) (time.Time, time.Time, error) {
	beforeValues, before := values[attributeNotBefore]
	afterValues, after := values[attributeNotAfter]
	if before != after {
		return time.Time{}, time.Time{}, ErrMalformed
	}
	if !before {
		return time.Time{}, time.Time{}, nil
	}
	parse := func(raw []byte) (time.Time, error) {
		value := string(raw)
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
			return time.Time{}, ErrMalformed
		}
		return parsed, nil
	}
	notBefore, err := parse(beforeValues[0])
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parse(afterValues[0])
	return notBefore, notAfter, err
}

// mapPolicy parses one closed exact policy record.
func mapPolicy(generation uint64, values map[string][][]byte) (dkim2model.Policy, error) {
	use, err := dkim2model.ParseProfileUse(string(values[attributeProfileUse][0]))
	if err != nil {
		return dkim2model.Policy{}, err
	}
	status, err := dkim2model.ParseRecordStatus(string(values[attributeRecordStatus][0]))
	if err != nil {
		return dkim2model.Policy{}, err
	}
	rollout, err := dkim2model.ParseRollout(string(values[attributeRollout][0]))
	if err != nil {
		return dkim2model.Policy{}, err
	}
	compatibility, err := dkim2model.ParseCompatibility(string(values[attributeCompatibility][0]))
	if err != nil {
		return dkim2model.Policy{}, err
	}
	feedback := ""
	if route := values[attributeFeedbackRouteID]; len(route) == 1 {
		feedback = string(route[0])
	}
	return dkim2model.NewPolicy(
		generation, string(values[attributeTenantID][0]), string(values[attributeSigningDomain][0]),
		use, string(values[attributeProfileID][0]), status, rollout, compatibility, feedback,
	)
}

// mapKeyMaterial constructs one protected record and clears intermediate private bytes.
func mapKeyMaterial(generation uint64, values map[string][][]byte) (*dkim2model.KeyMaterial, error) {
	use, err := dkim2model.ParseProfileUse(string(values[attributeProfileUse][0]))
	if err != nil {
		return nil, err
	}
	algorithm, err := dkim2model.ParseAlgorithm(string(values[attributeAlgorithm][0]))
	if err != nil {
		return nil, err
	}
	privatePKCS8 := append([]byte(nil), values[attributePrivatePKCS8][0]...)
	publicSPKI := append([]byte(nil), values[attributePublicKeySPKI][0]...)
	defer clear(privatePKCS8)
	defer clear(publicSPKI)
	pair, err := dkim2model.NewKeyPair(algorithm, privatePKCS8, publicSPKI)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pair.Close() }()
	return dkim2model.NewKeyMaterial(
		generation, string(values[attributeTenantID][0]), string(values[attributeSigningDomain][0]),
		use, string(values[attributeHandleID][0]), pair,
	)
}

// validateDatasetSize rejects oversized results before model retention.
func validateDatasetSize(entries []*ldap.Entry, limits Limits) error {
	total := 0
	for _, entry := range entries {
		if entry == nil {
			return ErrMalformed
		}
		for _, attribute := range entry.Attributes {
			if attribute == nil || len(attribute.Name) > limits.MaxAttributeBytes {
				return ErrMalformed
			}
			if total > limits.MaxDatasetBytes-len(attribute.Name) {
				return ErrMalformed
			}
			total += len(attribute.Name)
			for _, value := range attribute.ByteValues {
				if value == nil || len(value) > limits.MaxAttributeBytes || total > limits.MaxDatasetBytes-len(value) {
					return ErrMalformed
				}
				total += len(value)
			}
		}
	}
	return nil
}

// clearSensitiveEntries clears every raw private-key value owned by a search result.
func clearSensitiveEntries(entries []*ldap.Entry) {
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		for _, attribute := range entry.Attributes {
			if attribute == nil || !strings.EqualFold(attribute.Name, attributePrivatePKCS8) {
				continue
			}
			for index := range attribute.ByteValues {
				clear(attribute.ByteValues[index])
				attribute.ByteValues[index] = nil
			}
			for index := range attribute.Values {
				attribute.Values[index] = ""
			}
			attribute.ByteValues = nil
			attribute.Values = nil
		}
	}
}
