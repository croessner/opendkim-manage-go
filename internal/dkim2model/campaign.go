package dkim2model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

const bindingIdentityRedacted = "dkim2model.BindingIdentity{redacted}"

// BindingIdentity is one redacted exact administrative binding changed by a campaign successor.
type BindingIdentity struct {
	tenant string
	domain string
	use    ProfileUse
}

func (b BindingIdentity) TenantID() string { return b.tenant }
func (b BindingIdentity) Domain() string   { return b.domain }
func (b BindingIdentity) Use() ProfileUse  { return b.use }
func (BindingIdentity) String() string     { return bindingIdentityRedacted }
func (BindingIdentity) GoString() string   { return bindingIdentityRedacted }
func (BindingIdentity) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, bindingIdentityRedacted)
}
func (BindingIdentity) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// ActiveBindings returns the bounded exact administrative bindings of one committed generation.
func ActiveBindings(generation *Generation, maximumBindings int) ([]BindingIdentity, error) {
	if generation == nil || generation.State() != DatasetStateCommitted || maximumBindings <= 0 {
		return nil, ErrInvalid
	}
	bindings := make([]BindingIdentity, 0, min(len(generation.policies), maximumBindings))
	seen := make(map[string]struct{}, min(len(generation.policies), maximumBindings))
	for _, policy := range generation.policies {
		if policy.Status() != RecordStatusActive {
			continue
		}
		profile, found := generation.ProfileByID(policy.ProfileID())
		if !found || profile.Status() != RecordStatusActive || profile.SigningDomain() != policy.SigningDomain() ||
			!policy.Use().SupportsNativeKeyCustody() {
			return nil, ErrInvalid
		}
		identity := policy.TenantID() + "\x00" + policy.SigningDomain() + "\x00" + string(policy.Use())
		if _, duplicate := seen[identity]; duplicate {
			return nil, ErrInvalid
		}
		seen[identity] = struct{}{}
		bindings = append(bindings, BindingIdentity{
			tenant: policy.TenantID(), domain: policy.SigningDomain(), use: policy.Use(),
		})
		if len(bindings) > maximumBindings {
			return nil, ErrInvalid
		}
	}
	if len(bindings) == 0 {
		return nil, ErrInvalid
	}
	slices.SortFunc(bindings, func(a, b BindingIdentity) int {
		return strings.Compare(a.tenant+"\x00"+a.domain+"\x00"+string(a.use), b.tenant+"\x00"+b.domain+"\x00"+string(b.use))
	})
	return bindings, nil
}

// ChangedActiveBindings proves a complete source-plus-one successor and returns every exact changed binding.
func ChangedActiveBindings(source, candidate *Generation, maximumBindings int) ([]BindingIdentity, error) {
	if source == nil || candidate == nil || source.Number() == ^uint64(0) ||
		candidate.Number() != source.Number()+1 || maximumBindings <= 0 ||
		(candidate.State() != DatasetStateStaging && candidate.State() != DatasetStateCommitted) ||
		len(source.profiles) != len(candidate.profiles) || len(source.policies) != len(candidate.policies) {
		return nil, ErrInvalid
	}
	for index := range source.profiles {
		if !sameProfileFacts(source.profiles[index], candidate.profiles[index]) {
			return nil, ErrInvalid
		}
	}
	for index := range source.policies {
		if !samePolicyFacts(source.policies[index], candidate.policies[index]) {
			return nil, ErrInvalid
		}
	}
	var changed []BindingIdentity
	for _, sourceProfile := range source.profiles {
		candidateProfile, found := candidate.ProfileByID(sourceProfile.ID())
		if !found {
			return nil, ErrInvalid
		}
		sourceCredentials := credentialsForProfile(source, sourceProfile.ID())
		candidateCredentials := credentialsForProfile(candidate, candidateProfile.ID())
		if len(sourceCredentials) != len(candidateCredentials) {
			return nil, ErrInvalid
		}
		slices.SortFunc(sourceCredentials, compareCredentialAlgorithm)
		slices.SortFunc(candidateCredentials, compareCredentialAlgorithm)
		unchanged := true
		for index := range sourceCredentials {
			if sourceCredentials[index].Algorithm() != candidateCredentials[index].Algorithm() {
				return nil, ErrInvalid
			}
			if !sameCredentialAndMaterial(source, sourceCredentials[index], candidate, candidateCredentials[index]) {
				unchanged = false
			}
		}
		if unchanged {
			continue
		}
		var policy Policy
		matches := 0
		for _, candidatePolicy := range source.policies {
			if candidatePolicy.ProfileID() == sourceProfile.ID() {
				policy = candidatePolicy
				matches++
			}
		}
		if matches != 1 || policy.Status() != RecordStatusActive || sourceProfile.Status() != RecordStatusActive || !policy.Use().SupportsNativeKeyCustody() {
			return nil, ErrInvalid
		}
		for index := range sourceCredentials {
			if sourceCredentials[index].Selector() == candidateCredentials[index].Selector() ||
				sourceCredentials[index].HandleID() == candidateCredentials[index].HandleID() {
				return nil, ErrInvalid
			}
		}
		changed = append(changed, BindingIdentity{tenant: policy.TenantID(), domain: policy.SigningDomain(), use: policy.Use()})
		if len(changed) > maximumBindings {
			return nil, ErrInvalid
		}
	}
	slices.SortFunc(changed, func(a, b BindingIdentity) int {
		return strings.Compare(a.tenant+"\x00"+a.domain+"\x00"+string(a.use), b.tenant+"\x00"+b.domain+"\x00"+string(b.use))
	})
	return changed, nil
}

func sameProfileFacts(a, b Profile) bool {
	if a.ID() != b.ID() || a.SigningDomain() != b.SigningDomain() || a.Status() != b.Status() {
		return false
	}
	ab, aa, ap := a.ValidityWindow()
	bb, ba, bp := b.ValidityWindow()
	return ap == bp && (!ap || ab.Equal(bb) && aa.Equal(ba))
}

func samePolicyFacts(a, b Policy) bool {
	return a.TenantID() == b.TenantID() && a.SigningDomain() == b.SigningDomain() && a.Use() == b.Use() &&
		a.ProfileID() == b.ProfileID() && a.Status() == b.Status() && a.Rollout() == b.Rollout() &&
		a.Compatibility() == b.Compatibility() && a.FeedbackRouteID() == b.FeedbackRouteID()
}

func credentialsForProfile(g *Generation, profileID string) []Credential {
	var result []Credential
	for _, credential := range g.credentials {
		if credential.ProfileID() == profileID {
			result = append(result, cloneCredential(credential))
		}
	}
	return result
}

func compareCredentialAlgorithm(a, b Credential) int {
	return strings.Compare(string(a.Algorithm()), string(b.Algorithm()))
}

func sameCredentialAndMaterial(left *Generation, lc Credential, right *Generation, rc Credential) bool {
	if lc.ProfileID() != rc.ProfileID() || lc.Selector() != rc.Selector() || lc.Algorithm() != rc.Algorithm() ||
		lc.HandleID() != rc.HandleID() || !bytes.Equal(lc.publicSPKI, rc.publicSPKI) {
		return false
	}
	lm, lok := left.KeyMaterialByHandle(lc.HandleID())
	rm, rok := right.KeyMaterialByHandle(rc.HandleID())
	if !lok || !rok {
		if lm != nil {
			_ = lm.Close()
		}
		if rm != nil {
			_ = rm.Close()
		}
		return false
	}
	defer func() { _ = lm.Close(); _ = rm.Close() }()
	lp, rp := lm.PrivatePKCS8DER(), rm.PrivatePKCS8DER()
	defer clear(lp)
	defer clear(rp)
	return lm.TenantID() == rm.TenantID() && lm.SigningDomain() == rm.SigningDomain() && lm.Use() == rm.Use() &&
		lm.HandleID() == rm.HandleID() && lm.Algorithm() == rm.Algorithm() && bytes.Equal(lp, rp)
}
