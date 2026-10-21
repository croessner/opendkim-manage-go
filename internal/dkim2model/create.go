package dkim2model

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"time"
)

// CreateCandidateIntent describes the exact additive, inactive administrative request to recover.
type CreateCandidateIntent struct {
	TenantID        string
	Domains         []string
	Use             ProfileUse
	Algorithms      []Algorithm
	RSABits         int
	Selectors       []string
	FeedbackRouteID string
	MaximumBindings int
}

// ValidateCreateCandidateIntent proves an unchanged source plus exactly the requested fresh inactive bindings.
// Reconstructing with stored key owners performs no randomness or key generation.
func ValidateCreateCandidateIntent(source, candidate *Generation, history LineageHistory, intent CreateCandidateIntent) ([]BindingIdentity, error) {
	if source == nil || candidate == nil || source.State() != DatasetStateCommitted ||
		source.Number() == ^uint64(0) || candidate.Number() != source.Number()+1 ||
		(candidate.State() != DatasetStateStaging && candidate.State() != DatasetStateCommitted) ||
		!history.Complete || intent.validate() != nil ||
		len(candidate.profiles) != len(source.profiles)+len(intent.Domains) ||
		len(candidate.policies) != len(source.policies)+len(intent.Domains) {
		return nil, ErrInvalid
	}
	lineage, err := history.Clone()
	if err != nil || validateGenerationLineageProjection(source, lineage, source.Number()) != nil ||
		validateGenerationLineageProjection(candidate, lineage, candidate.Number()) != nil {
		return nil, ErrInvalid
	}
	for _, fact := range lineage.Facts {
		if fact.generation > candidate.Number() {
			return nil, ErrInvalid
		}
	}
	builder, err := source.NextBuilder(candidate.Number(), candidate.State())
	if err != nil {
		return nil, ErrInvalid
	}
	defer func() { _ = builder.Close() }()
	bindings := make([]BindingIdentity, 0, len(intent.Domains))
	allocatedPublicKeys := make(map[string]struct{}, len(intent.Domains)*len(intent.Algorithms))
	for _, domain := range intent.Domains {
		if err := intent.appendStoredBinding(builder, source, candidate, lineage, domain, allocatedPublicKeys); err != nil {
			return nil, ErrInvalid
		}
		bindings = append(bindings, BindingIdentity{tenant: intent.TenantID, domain: domain, use: intent.Use})
	}
	expected, err := builder.Build()
	if err != nil {
		return nil, ErrInvalid
	}
	defer func() { _ = expected.Close() }()
	if !expected.Equivalent(candidate) {
		return nil, ErrInvalid
	}
	return bindings, nil
}

// validate rejects incomplete, duplicate, noncanonical, or over-budget create scope before inspecting keys.
func (i CreateCandidateIntent) validate() error {
	if ValidateIdentifier(i.TenantID) != nil || !i.Use.SupportsNativeKeyCustody() ||
		i.MaximumBindings <= 0 || len(i.Domains) == 0 || len(i.Domains) > i.MaximumBindings ||
		len(i.Algorithms) == 0 || len(i.Algorithms) > 2 ||
		len(i.Selectors) > 0 && (len(i.Domains) != 1 || len(i.Selectors) != len(i.Algorithms)) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(i.Domains))
	for _, domain := range i.Domains {
		if ValidateCanonicalDNSName(domain) != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[domain]; duplicate {
			return ErrInvalid
		}
		seen[domain] = struct{}{}
	}
	for index, algorithm := range i.Algorithms {
		if !algorithm.Known() || slices.Contains(i.Algorithms[:index], algorithm) ||
			algorithm == AlgorithmRSASHA256 && (i.RSABits < MinRSABits || i.RSABits > MaxRSABits || i.RSABits%8 != 0) {
			return ErrInvalid
		}
	}
	for _, selector := range i.Selectors {
		if ValidateCanonicalDNSName(selector) != nil {
			return ErrInvalid
		}
	}
	return nil
}

// appendStoredBinding permits only a new disabled profile with off/strict policy and exact stored key ownership.
func (i CreateCandidateIntent) appendStoredBinding(builder *Builder, source, candidate *Generation, history LineageHistory, domain string, allocatedPublicKeys map[string]struct{}) error {
	var profileID string
	for _, policy := range source.policies {
		if policy.TenantID() == i.TenantID && policy.SigningDomain() == domain && policy.Use() == i.Use {
			return ErrInvalid
		}
	}
	for _, policy := range candidate.policies {
		if policy.TenantID() == i.TenantID && policy.SigningDomain() == domain && policy.Use() == i.Use {
			if profileID != "" {
				return ErrInvalid
			}
			profileID = policy.ProfileID()
		}
	}
	if profileID == "" {
		return ErrInvalid
	}
	if _, found := source.ProfileByID(profileID); found {
		return ErrInvalid
	}
	profile, err := NewProfile(candidate.Number(), profileID, domain, RecordStatusDisabled, time.Time{}, time.Time{})
	if err != nil {
		return ErrInvalid
	}
	policy, err := NewPolicy(candidate.Number(), i.TenantID, domain, i.Use, profileID,
		RecordStatusDisabled, RolloutOff, CompatibilityStrict, i.FeedbackRouteID)
	if err != nil {
		return ErrInvalid
	}
	credentials := credentialsForProfile(candidate, profileID)
	if len(credentials) != len(i.Algorithms) {
		return ErrInvalid
	}
	materials := make([]*KeyMaterial, 0, len(credentials))
	defer func() { closeKeyMaterials(materials) }()
	for _, credential := range credentials {
		index := slices.Index(i.Algorithms, credential.Algorithm())
		if index < 0 || len(i.Selectors) > 0 && i.Selectors[index] != credential.Selector() ||
			!createCredentialSizeMatches(credential, i.RSABits) {
			return ErrInvalid
		}
		identity := string(credential.Algorithm()) + "\x00" + string(credential.publicSPKI)
		if _, duplicate := allocatedPublicKeys[identity]; duplicate {
			return ErrInvalid
		}
		allocatedPublicKeys[identity] = struct{}{}
		for _, fact := range history.Facts {
			if fact.generation < candidate.Number() && (fact.selector == credential.Selector() ||
				fact.handle == credential.HandleID() ||
				fact.algorithm == credential.Algorithm() && bytes.Equal(fact.publicSPKI, credential.publicSPKI)) {
				return ErrInvalid
			}
		}
		material, found := candidate.KeyMaterialByHandle(credential.HandleID())
		if !found {
			return ErrInvalid
		}
		materials = append(materials, material)
	}
	return builder.AddProfileWithKeys(profile, credentials, policy, materials)
}

// createCredentialSizeMatches preserves the requested RSA size without opening private material.
func createCredentialSizeMatches(credential Credential, bits int) bool {
	if credential.Algorithm() != AlgorithmRSASHA256 {
		return true
	}
	public, err := x509.ParsePKIXPublicKey(credential.publicSPKI)
	key, ok := public.(*rsa.PublicKey)
	return err == nil && ok && key.N.BitLen() == bits
}
