package dkim2model

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	lineageRedacted     = "dkim2model.LineageFact{redacted}"
	eligibilityRedacted = "dkim2model.EligibilityDecision{redacted}"
)

// HistoricalIdentifierLookup proves selector and handle non-reuse across complete retained history.
type HistoricalIdentifierLookup interface {
	SelectorUsed(string) (bool, error)
	HandleUsed(string) (bool, error)
}

// KeyGenerator constructs one independently owned native key pair.
type KeyGenerator func(Algorithm, int, io.Reader) (*KeyPair, error)

// RotationPlan contains the exact protected inputs for one pure candidate build.
type RotationPlan struct {
	Current            *Generation
	NextGeneration     uint64
	TenantID           string
	Domain             string
	Use                ProfileUse
	Algorithms         []Algorithm
	RSABits            int
	AllocationAttempts int
	Random             io.Reader
	History            HistoricalIdentifierLookup
	Generate           KeyGenerator
}

// RotationLimits contains every operator-selected bound used by global planning.
type RotationLimits struct {
	RotateAfter        time.Duration
	MaximumClockSkew   time.Duration
	AllocationAttempts int
	RSABits            int
	MaximumBindings    int
}

// Validate rejects absent or internally inconsistent operational limits.
func (l RotationLimits) Validate() error {
	if l.RotateAfter <= 0 || l.MaximumClockSkew < 0 || l.AllocationAttempts <= 0 ||
		l.RSABits < MinRSABits || l.RSABits > MaxRSABits || l.RSABits%8 != 0 || l.MaximumBindings <= 0 {
		return ErrInvalid
	}
	return nil
}

// GlobalRotationPlan contains all inputs for one complete all-domain successor.
type GlobalRotationPlan struct {
	Current        *Generation
	NextGeneration uint64
	Now            time.Time
	History        LineageHistory
	Identifiers    HistoricalIdentifierLookup
	Random         io.Reader
	Limits         RotationLimits
	Generate       KeyGenerator
}

// PlanGlobalRotation rotates every due active binding in exactly one complete successor.
func PlanGlobalRotation(plan GlobalRotationPlan) (*Generation, []EligibilityDecision, error) {
	if plan.Current == nil || plan.Current.Number() == ^uint64(0) ||
		plan.NextGeneration != plan.Current.Number()+1 || plan.Now.Location() != time.UTC ||
		!plan.History.Complete || plan.Identifiers == nil || plan.Random == nil || plan.Limits.Validate() != nil {
		return nil, nil, ErrInvalid
	}
	decisions, err := EligibleBindings(plan.Now, plan.Current, plan.History, plan.Limits)
	if err != nil {
		return nil, nil, err
	}
	if len(decisions) == 0 {
		return nil, nil, nil
	}
	builder, err := plan.Current.NextBuilder(plan.NextGeneration, DatasetStateStaging)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = builder.Close() }()
	replacer := newCampaignKeyReplacer(plan.Current, plan.NextGeneration, plan.Random, plan.Identifiers, plan.Limits, plan.Generate)
	for _, decision := range decisions {
		_, profile, credentials, bindingErr := exactActiveBinding(plan.Current, decision.tenant, decision.domain, decision.use)
		if bindingErr != nil {
			return nil, nil, bindingErr
		}
		algorithms := make([]Algorithm, len(credentials))
		for index := range credentials {
			algorithms[index] = credentials[index].Algorithm()
		}
		slices.SortFunc(algorithms, CompareAlgorithms)
		if err := replacer.replace(builder, profile, decision.tenant, decision.domain, decision.use, algorithms); err != nil {
			return nil, nil, err
		}
	}
	candidate, err := builder.Build()
	if err != nil {
		return nil, nil, err
	}
	return candidate, decisions, nil
}

// PlanRotation replaces one complete active binding while preserving the detached snapshot.
func PlanRotation(plan RotationPlan) (*Generation, error) {
	if plan.Current == nil || plan.Current.Number() == ^uint64(0) ||
		plan.NextGeneration != plan.Current.Number()+1 || plan.History == nil ||
		plan.Random == nil || plan.AllocationAttempts <= 0 || ValidateIdentifier(plan.TenantID) != nil ||
		ValidateCanonicalDNSName(plan.Domain) != nil || !plan.Use.SupportsNativeKeyCustody() {
		return nil, ErrInvalid
	}
	policy, profile, credentials, err := exactActiveBinding(plan.Current, plan.TenantID, plan.Domain, plan.Use)
	if err != nil {
		return nil, err
	}
	currentAlgorithms := make([]Algorithm, len(credentials))
	for index, credential := range credentials {
		currentAlgorithms[index] = credential.Algorithm()
	}
	slices.SortFunc(currentAlgorithms, func(left, right Algorithm) int { return algorithmRank(left) - algorithmRank(right) })
	requestedInput := plan.Algorithms
	if len(requestedInput) == 0 {
		requestedInput = currentAlgorithms
	}
	// A rotation replaces every current credential and may extend the
	// algorithm set, for example with mldsa44-ed25519-sha512; it never drops
	// an algorithm.
	requested, err := canonicalAlgorithmSet(requestedInput)
	if err != nil || !containsEveryAlgorithm(requested, currentAlgorithms) {
		return nil, ErrInvalid
	}
	if slices.Contains(requested, AlgorithmRSASHA256) &&
		(plan.RSABits < MinRSABits || plan.RSABits > MaxRSABits || plan.RSABits%8 != 0) {
		return nil, ErrInvalid
	}

	usedSelectors := make(map[string]struct{}, len(plan.Current.credentials)+len(requested))
	usedHandles := make(map[string]struct{}, len(plan.Current.handles)+len(requested))
	for _, credential := range plan.Current.credentials {
		usedSelectors[credential.Selector()] = struct{}{}
	}
	for _, handle := range plan.Current.handles {
		usedHandles[handle.ID()] = struct{}{}
	}
	selectors := make([]string, len(requested))
	handles := make([]string, len(requested))
	for index := range requested {
		selectors[index], err = allocateHistoricalIDBounded("dkim2", plan.Random, usedSelectors, plan.History.SelectorUsed, plan.AllocationAttempts)
		if err != nil {
			return nil, err
		}
		handles[index], err = allocateHistoricalIDBounded("key", plan.Random, usedHandles, plan.History.HandleUsed, plan.AllocationAttempts)
		if err != nil {
			return nil, err
		}
	}

	generate := plan.Generate
	if generate == nil {
		generate = GenerateKeyPair
	}
	newCredentials := make([]Credential, 0, len(requested))
	newMaterials := make([]*KeyMaterial, 0, len(requested))
	defer closeKeyMaterials(newMaterials)
	for index, algorithm := range requested {
		pair, pairErr := generate(algorithm, plan.RSABits, plan.Random)
		if pairErr != nil {
			if pair != nil {
				_ = pair.Close()
			}
			return nil, errors.New("generate protected DKIM2 rotation key")
		}
		if pair == nil {
			return nil, errors.New("generate protected DKIM2 rotation key")
		}
		public := pair.PublicSPKIDER()
		credential, credentialErr := NewCredential(plan.NextGeneration, profile.ID(), selectors[index], algorithm, public, handles[index])
		clear(public)
		material, materialErr := NewKeyMaterial(plan.NextGeneration, policy.TenantID(), plan.Domain, plan.Use, handles[index], pair)
		_ = pair.Close()
		if credentialErr != nil || materialErr != nil {
			if material != nil {
				_ = material.Close()
			}
			return nil, ErrInvalid
		}
		newCredentials = append(newCredentials, credential)
		newMaterials = append(newMaterials, material)
	}
	builder, err := plan.Current.NextBuilder(plan.NextGeneration, DatasetStateStaging)
	if err != nil {
		return nil, err
	}
	defer func() { _ = builder.Close() }()
	if err := builder.ReplaceProfileKeys(profile.ID(), newCredentials, newMaterials); err != nil {
		return nil, err
	}
	return builder.Build()
}

// GlobalExtensionPlan contains all inputs for one operator-requested
// all-binding algorithm-set extension successor.
type GlobalExtensionPlan struct {
	Current        *Generation
	NextGeneration uint64
	Algorithms     []Algorithm
	Identifiers    HistoricalIdentifierLookup
	Random         io.Reader
	Limits         RotationLimits
	Generate       KeyGenerator
}

// PlanGlobalExtension rotates every active native binding into fresh keys of
// exactly the requested algorithm set in one complete successor. The request
// must be a superset of every binding's current set, so no binding ever loses
// an algorithm. When every binding already carries exactly the requested set,
// nothing is extended and no candidate is returned, which keeps a repeated
// campaign idempotent.
func PlanGlobalExtension(plan GlobalExtensionPlan) (*Generation, []BindingIdentity, error) {
	if plan.Current == nil || plan.Current.Number() == ^uint64(0) ||
		plan.NextGeneration != plan.Current.Number()+1 || plan.Identifiers == nil ||
		plan.Random == nil || plan.Limits.Validate() != nil {
		return nil, nil, ErrInvalid
	}
	requested, err := canonicalAlgorithmSet(plan.Algorithms)
	if err != nil {
		return nil, nil, err
	}
	bindings, err := ActiveBindings(plan.Current, plan.Limits.MaximumBindings)
	if err != nil {
		return nil, nil, err
	}
	profiles := make([]Profile, len(bindings))
	extends := false
	for index, binding := range bindings {
		_, profile, credentials, bindingErr := exactActiveBinding(plan.Current, binding.tenant, binding.domain, binding.use)
		if bindingErr != nil {
			return nil, nil, bindingErr
		}
		current := make([]Algorithm, len(credentials))
		for credentialIndex, credential := range credentials {
			current[credentialIndex] = credential.Algorithm()
		}
		if !containsEveryAlgorithm(requested, current) {
			return nil, nil, ErrInvalid
		}
		extends = extends || len(credentials) < len(requested)
		profiles[index] = profile
	}
	if !extends {
		return nil, nil, nil
	}
	builder, err := plan.Current.NextBuilder(plan.NextGeneration, DatasetStateStaging)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = builder.Close() }()
	replacer := newCampaignKeyReplacer(plan.Current, plan.NextGeneration, plan.Random, plan.Identifiers, plan.Limits, plan.Generate)
	for index, binding := range bindings {
		if err := replacer.replace(builder, profiles[index], binding.tenant, binding.domain, binding.use, requested); err != nil {
			return nil, nil, err
		}
	}
	candidate, err := builder.Build()
	if err != nil {
		return nil, nil, err
	}
	return candidate, bindings, nil
}

// canonicalAlgorithmSet returns a sorted detached copy of a nonempty, bounded
// set of known algorithms and rejects duplicates.
func canonicalAlgorithmSet(algorithms []Algorithm) ([]Algorithm, error) {
	if len(algorithms) == 0 || len(algorithms) > MaxCredentialsPerProfile {
		return nil, ErrInvalid
	}
	result := slices.Clone(algorithms)
	slices.SortFunc(result, CompareAlgorithms)
	for index, algorithm := range result {
		if !algorithm.Known() || index > 0 && algorithm == result[index-1] {
			return nil, ErrInvalid
		}
	}
	return result, nil
}

// containsEveryAlgorithm reports whether requested keeps every current algorithm.
func containsEveryAlgorithm(requested, current []Algorithm) bool {
	for _, algorithm := range current {
		if !slices.Contains(requested, algorithm) {
			return false
		}
	}
	return true
}

// campaignKeyReplacer allocates fresh historical identifiers and keys for the
// bindings of one campaign successor. It reserves every identifier it hands
// out, so no two bindings of one successor share a selector or handle.
type campaignKeyReplacer struct {
	next          uint64
	random        io.Reader
	identifiers   HistoricalIdentifierLookup
	limits        RotationLimits
	generate      KeyGenerator
	usedSelectors map[string]struct{}
	usedHandles   map[string]struct{}
}

// newCampaignKeyReplacer reserves every current selector and handle before
// any successor identifier is allocated.
func newCampaignKeyReplacer(current *Generation, next uint64, random io.Reader, identifiers HistoricalIdentifierLookup,
	limits RotationLimits, generate KeyGenerator,
) *campaignKeyReplacer {
	if generate == nil {
		generate = GenerateKeyPair
	}
	replacer := &campaignKeyReplacer{next: next, random: random, identifiers: identifiers, limits: limits, generate: generate,
		usedSelectors: make(map[string]struct{}, len(current.credentials)), usedHandles: make(map[string]struct{}, len(current.handles))}
	for _, credential := range current.credentials {
		replacer.usedSelectors[credential.Selector()] = struct{}{}
	}
	for _, handle := range current.handles {
		replacer.usedHandles[handle.ID()] = struct{}{}
	}
	return replacer
}

// replace generates one fresh credential per algorithm for one exact active
// binding and atomically replaces the profile keys in builder. Protected key
// material is closed on every path.
func (r *campaignKeyReplacer) replace(builder *Builder, profile Profile, tenant, domain string, use ProfileUse, algorithms []Algorithm) error {
	newCredentials := make([]Credential, 0, len(algorithms))
	newMaterials := make([]*KeyMaterial, 0, len(algorithms))
	defer func() { closeKeyMaterials(newMaterials) }()
	for _, algorithm := range algorithms {
		selector, err := allocateHistoricalIDBounded("dkim2", r.random, r.usedSelectors, r.identifiers.SelectorUsed, r.limits.AllocationAttempts)
		if err != nil {
			return err
		}
		handle, err := allocateHistoricalIDBounded("key", r.random, r.usedHandles, r.identifiers.HandleUsed, r.limits.AllocationAttempts)
		if err != nil {
			return err
		}
		pair, err := r.generate(algorithm, r.limits.RSABits, r.random)
		if err != nil || pair == nil {
			if pair != nil {
				_ = pair.Close()
			}
			return errors.New("generate protected DKIM2 rotation key")
		}
		public := pair.PublicSPKIDER()
		credential, credentialErr := NewCredential(r.next, profile.ID(), selector, algorithm, public, handle)
		clear(public)
		material, materialErr := NewKeyMaterial(r.next, tenant, domain, use, handle, pair)
		_ = pair.Close()
		if credentialErr != nil || materialErr != nil {
			if material != nil {
				_ = material.Close()
			}
			return ErrInvalid
		}
		newCredentials = append(newCredentials, credential)
		newMaterials = append(newMaterials, material)
	}
	return builder.ReplaceProfileKeys(profile.ID(), newCredentials, newMaterials)
}

func exactActiveBinding(generation *Generation, tenant, domain string, use ProfileUse) (Policy, Profile, []Credential, error) {
	var policy Policy
	count := 0
	for _, candidate := range generation.policies {
		if candidate.TenantID() == tenant && candidate.SigningDomain() == domain && candidate.Use() == use {
			policy = candidate
			count++
		}
	}
	if count != 1 || policy.Status() != RecordStatusActive {
		return Policy{}, Profile{}, nil, ErrInvalid
	}
	profile, found := generation.ProfileByID(policy.ProfileID())
	if !found || profile.Status() != RecordStatusActive {
		return Policy{}, Profile{}, nil, ErrInvalid
	}
	profilePolicyCount := 0
	for _, candidate := range generation.policies {
		if candidate.ProfileID() == profile.ID() {
			profilePolicyCount++
		}
	}
	if profilePolicyCount != 1 {
		return Policy{}, Profile{}, nil, ErrInvalid
	}
	var credentials []Credential
	for _, credential := range generation.credentials {
		if credential.ProfileID() == profile.ID() {
			credentials = append(credentials, cloneCredential(credential))
		}
	}
	if len(credentials) == 0 {
		return Policy{}, Profile{}, nil, ErrInvalid
	}
	return policy, profile, credentials, nil
}

func allocateHistoricalIDBounded(prefix string, random io.Reader, used map[string]struct{}, historical func(string) (bool, error), attempts int) (string, error) {
	if attempts <= 0 {
		return "", ErrInvalid
	}
	for range attempts {
		buffer := make([]byte, 12)
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", errors.New("read protected rotation randomness")
		}
		candidate := prefix + "-" + hex.EncodeToString(buffer)
		clear(buffer)
		if _, exists := used[candidate]; exists {
			continue
		}
		exists, err := historical(candidate)
		if err != nil {
			return "", errors.New("historical identifier check failed")
		}
		if exists {
			continue
		}
		used[candidate] = struct{}{}
		return candidate, nil
	}
	return "", errors.New("could not allocate a unique historical DKIM2 identifier")
}

// LineageFact is one redacted retained credential and exact root creation-time projection.
type LineageFact struct {
	generation uint64
	created    string
	tenant     string
	domain     string
	use        ProfileUse
	selector   string
	algorithm  Algorithm
	publicSPKI []byte
	handle     string
}

// NewLineageFact validates one exact canonical root timestamp and credential-lineage fact.
func NewLineageFact(generation uint64, created, tenant, domain string, use ProfileUse, selector string, algorithm Algorithm, publicSPKI []byte, handle string) (LineageFact, error) {
	if generation == 0 || ValidateIdentifier(tenant) != nil || ValidateCanonicalDNSName(domain) != nil ||
		!use.SupportsNativeKeyCustody() || ValidateCanonicalDNSName(selector) != nil ||
		!algorithm.Known() || ValidateIdentifier(handle) != nil || parseGeneralizedTime(created).IsZero() {
		return LineageFact{}, ErrInvalid
	}
	if _, err := canonicalDNSPublicBytes(algorithm, publicSPKI); err != nil {
		return LineageFact{}, ErrInvalid
	}
	return LineageFact{generation: generation, created: created, tenant: tenant, domain: domain, use: use,
		selector: selector, algorithm: algorithm, publicSPKI: bytes.Clone(publicSPKI), handle: handle}, nil
}

func (LineageFact) String() string                 { return lineageRedacted }
func (LineageFact) GoString() string               { return lineageRedacted }
func (LineageFact) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, lineageRedacted) }
func (LineageFact) MarshalJSON() ([]byte, error)   { return json.Marshal(struct{}{}) }

// LineageHistory explicitly marks whether the retained history projection is complete.
type LineageHistory struct {
	Complete bool
	Facts    []LineageFact
}

// Clone returns independently owned validated lineage facts.
func (h LineageHistory) Clone() (LineageHistory, error) {
	result := LineageHistory{Complete: h.Complete, Facts: make([]LineageFact, 0, len(h.Facts))}
	for _, fact := range h.Facts {
		clone, err := NewLineageFact(fact.generation, fact.created, fact.tenant, fact.domain, fact.use,
			fact.selector, fact.algorithm, fact.publicSPKI, fact.handle)
		if err != nil {
			return LineageHistory{}, ErrInvalid
		}
		result.Facts = append(result.Facts, clone)
	}
	return result, nil
}

// EligibilityDecision identifies at most one due canonical binding without protected lineage details.
type EligibilityDecision struct {
	due    bool
	domain string
	tenant string
	use    ProfileUse
	since  time.Time
}

func (d EligibilityDecision) Due() bool      { return d.due }
func (d EligibilityDecision) Domain() string { return d.domain }

// TenantID returns the exact selected administrative tenant.
func (d EligibilityDecision) TenantID() string { return d.tenant }

// Use returns the exact selected profile-use binding.
func (d EligibilityDecision) Use() ProfileUse { return d.use }
func (EligibilityDecision) String() string    { return eligibilityRedacted }
func (EligibilityDecision) GoString() string  { return eligibilityRedacted }
func (EligibilityDecision) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, eligibilityRedacted)
}
func (EligibilityDecision) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// EligibleBindings returns every due active binding under one complete lineage and typed limit set.
func EligibleBindings(now time.Time, current *Generation, history LineageHistory, limits RotationLimits) ([]EligibilityDecision, error) {
	if current == nil || now.Location() != time.UTC || !history.Complete || limits.Validate() != nil {
		return nil, ErrInvalid
	}
	active := 0
	var due []EligibilityDecision
	for _, policy := range current.policies {
		if policy.Status() != RecordStatusActive {
			continue
		}
		active++
		if active > limits.MaximumBindings {
			return nil, ErrInvalid
		}
		profile, found := current.ProfileByID(policy.ProfileID())
		if !found || profile.Status() != RecordStatusActive {
			return nil, ErrInvalid
		}
		credentials := make([]Credential, 0, 2)
		for _, credential := range current.credentials {
			if credential.ProfileID() == profile.ID() {
				credentials = append(credentials, credential)
			}
		}
		if len(credentials) == 0 {
			return nil, ErrInvalid
		}
		var bindingSince time.Time
		for _, credential := range credentials {
			var earliest time.Time
			seen := make(map[uint64]struct{})
			for _, fact := range history.Facts {
				if fact.tenant != policy.TenantID() || fact.domain != policy.SigningDomain() || fact.use != policy.Use() ||
					fact.selector != credential.Selector() || fact.algorithm != credential.Algorithm() || fact.handle != credential.HandleID() ||
					!bytes.Equal(fact.publicSPKI, credential.publicSPKI) {
					continue
				}
				if _, duplicate := seen[fact.generation]; duplicate {
					return nil, ErrInvalid
				}
				seen[fact.generation] = struct{}{}
				created := parseGeneralizedTime(fact.created)
				if created.IsZero() || created.After(now.Add(limits.MaximumClockSkew)) {
					return nil, ErrInvalid
				}
				if earliest.IsZero() || created.Before(earliest) {
					earliest = created
				}
			}
			if earliest.IsZero() {
				return nil, ErrInvalid
			}
			if bindingSince.IsZero() || earliest.Before(bindingSince) {
				bindingSince = earliest
			}
		}
		if !bindingSince.Add(limits.RotateAfter).After(now) {
			due = append(due, EligibilityDecision{due: true, domain: policy.SigningDomain(), tenant: policy.TenantID(), use: policy.Use(), since: bindingSince})
		}
	}
	slices.SortFunc(due, func(left, right EligibilityDecision) int {
		return strings.Compare(left.tenant+"\x00"+left.domain+"\x00"+string(left.use), right.tenant+"\x00"+right.domain+"\x00"+string(right.use))
	})
	return due, nil
}

func parseGeneralizedTime(value string) time.Time {
	if len(value) != 15 {
		return time.Time{}
	}
	parsed, err := time.Parse("20060102150405Z", value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format("20060102150405Z") != value {
		return time.Time{}
	}
	return parsed
}
