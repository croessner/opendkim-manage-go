package dkim2model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"
)

const (
	lifecycleBindingRedacted     = "dkim2model.LifecycleBinding{redacted}"
	lifecycleCredentialRedacted  = "dkim2model.LifecycleCredential{redacted}"
	retirementTransitionRedacted = "dkim2model.RetirementTransition{redacted}"
	rollbackTransitionRedacted   = "dkim2model.ForwardRollbackTransition{redacted}"
	retirementEvidenceRedacted   = "dkim2model.RetirementEvidence{redacted}"
	lifecycleObservationRedacted = "dkim2model.LifecycleObservation{redacted}"
)

// TransitionIntent identifies one exact explicit lifecycle mutation.
type TransitionIntent uint8

const (
	// TransitionIntentRetirement removes only a proven predecessor's DNS records.
	TransitionIntentRetirement TransitionIntent = iota + 1
	// TransitionIntentForwardRollback rebases one retained binding into a new generation.
	TransitionIntentForwardRollback
)

// Known reports whether the transition intent belongs to the closed vocabulary.
func (i TransitionIntent) Known() bool {
	return i == TransitionIntentRetirement || i == TransitionIntentForwardRollback
}

// LifecyclePhase identifies one bounded externally observable lifecycle state.
type LifecyclePhase uint8

const (
	// LifecyclePhaseIdle identifies a current generation without an active transition.
	LifecyclePhaseIdle LifecyclePhase = iota + 1
	// LifecyclePhaseStaged identifies a protected unreachable candidate.
	LifecyclePhaseStaged
	// LifecyclePhaseDNSPending identifies incomplete DNS publication or propagation.
	LifecyclePhaseDNSPending
	// LifecyclePhaseDNSConflict identifies exact DNS evidence that blocks progress.
	LifecyclePhaseDNSConflict
	// LifecyclePhaseCommittedUnreachable identifies a committed root before pointer reachability.
	LifecyclePhaseCommittedUnreachable
	// LifecyclePhaseActivated identifies an exact current committed generation.
	LifecyclePhaseActivated
	// LifecyclePhaseObserving identifies the mandatory post-activation overlap interval.
	LifecyclePhaseObserving
	// LifecyclePhaseRetireEligible identifies a proven overlap boundary before authorization.
	LifecyclePhaseRetireEligible
	// LifecyclePhaseRetired identifies exact absence of every predecessor DNS record.
	LifecyclePhaseRetired
)

// Known reports whether the lifecycle phase belongs to the closed vocabulary.
func (p LifecyclePhase) Known() bool {
	return p >= LifecyclePhaseIdle && p <= LifecyclePhaseRetired
}

// Name returns the exact bounded status token or an empty string for an unknown phase.
func (p LifecyclePhase) Name() string {
	switch p {
	case LifecyclePhaseIdle:
		return "idle"
	case LifecyclePhaseStaged:
		return "staged"
	case LifecyclePhaseDNSPending:
		return "dns-pending"
	case LifecyclePhaseDNSConflict:
		return "dns-conflict"
	case LifecyclePhaseCommittedUnreachable:
		return "committed-unreachable"
	case LifecyclePhaseActivated:
		return "activated"
	case LifecyclePhaseObserving:
		return "observing"
	case LifecyclePhaseRetireEligible:
		return "retire-eligible"
	case LifecyclePhaseRetired:
		return "retired"
	default:
		return ""
	}
}

// LifecycleBinding identifies one exact policy tuple without exposing key custody facts.
type LifecycleBinding struct {
	tenant    string
	domain    string
	use       ProfileUse
	profileID string
}

// TenantID returns the exact administrative tenant identifier.
func (b LifecycleBinding) TenantID() string { return b.tenant }

// Domain returns the exact canonical signing domain.
func (b LifecycleBinding) Domain() string { return b.domain }

// Use returns the exact administrative profile use.
func (b LifecycleBinding) Use() ProfileUse { return b.use }

func (LifecycleBinding) String() string   { return lifecycleBindingRedacted }
func (LifecycleBinding) GoString() string { return lifecycleBindingRedacted }
func (LifecycleBinding) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, lifecycleBindingRedacted)
}
func (LifecycleBinding) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// LifecycleCredential owns one detached public DNS expectation without its handle.
type LifecycleCredential struct {
	selector   string
	algorithm  Algorithm
	publicSPKI []byte
}

// Selector returns the exact canonical selector.
func (c LifecycleCredential) Selector() string { return c.selector }

// Algorithm returns the exact signing algorithm.
func (c LifecycleCredential) Algorithm() Algorithm { return c.algorithm }

// PublicSPKIDER returns detached canonical public SubjectPublicKeyInfo DER.
func (c LifecycleCredential) PublicSPKIDER() []byte { return bytes.Clone(c.publicSPKI) }

// DNSPublicKeyBytes returns detached algorithm-specific DNS p= bytes.
func (c LifecycleCredential) DNSPublicKeyBytes() []byte {
	result, _ := canonicalDNSPublicBytes(c.algorithm, c.publicSPKI)
	return result
}

func (LifecycleCredential) String() string   { return lifecycleCredentialRedacted }
func (LifecycleCredential) GoString() string { return lifecycleCredentialRedacted }
func (LifecycleCredential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, lifecycleCredentialRedacted)
}
func (LifecycleCredential) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// ObservationCredential contains only the selector and algorithm approved for status output.
type ObservationCredential struct {
	selector  string
	algorithm Algorithm
}

// NewObservationCredential validates one selector and algorithm status fact.
func NewObservationCredential(selector string, algorithm Algorithm) (ObservationCredential, error) {
	if ValidateCanonicalDNSName(selector) != nil || !algorithm.Known() {
		return ObservationCredential{}, ErrInvalid
	}
	return ObservationCredential{selector: selector, algorithm: algorithm}, nil
}

// Selector returns the exact canonical selector.
func (c ObservationCredential) Selector() string { return c.selector }

// Algorithm returns the exact signing algorithm.
func (c ObservationCredential) Algorithm() Algorithm { return c.algorithm }

// LifecycleObservation contains only bounded facts approved for operator status.
type LifecycleObservation struct {
	generation  uint64
	phase       LifecyclePhase
	domain      string
	credentials []ObservationCredential
}

// NewLifecycleObservation validates one bounded, non-secret status projection.
func NewLifecycleObservation(generation uint64, phase LifecyclePhase, domain string, credentials []ObservationCredential) (LifecycleObservation, error) {
	if generation == 0 || !phase.Known() || ValidateCanonicalDNSName(domain) != nil || len(credentials) > 2 {
		return LifecycleObservation{}, ErrInvalid
	}
	seenAlgorithms := make(map[Algorithm]struct{}, len(credentials))
	seenSelectors := make(map[string]struct{}, len(credentials))
	for _, credential := range credentials {
		if !credential.algorithm.Known() || ValidateCanonicalDNSName(credential.selector) != nil {
			return LifecycleObservation{}, ErrInvalid
		}
		if _, duplicate := seenAlgorithms[credential.algorithm]; duplicate {
			return LifecycleObservation{}, ErrInvalid
		}
		if _, duplicate := seenSelectors[credential.selector]; duplicate {
			return LifecycleObservation{}, ErrInvalid
		}
		seenAlgorithms[credential.algorithm] = struct{}{}
		seenSelectors[credential.selector] = struct{}{}
	}
	result := LifecycleObservation{generation: generation, phase: phase, domain: domain,
		credentials: append([]ObservationCredential(nil), credentials...)}
	return result, nil
}

// Generation returns the bounded observed generation number.
func (o LifecycleObservation) Generation() uint64 { return o.generation }

// Phase returns the exact closed lifecycle phase.
func (o LifecycleObservation) Phase() LifecyclePhase { return o.phase }

// Domain returns the canonical observed domain.
func (o LifecycleObservation) Domain() string { return o.domain }

// Credentials returns detached selector and algorithm facts.
func (o LifecycleObservation) Credentials() []ObservationCredential {
	return append([]ObservationCredential(nil), o.credentials...)
}

func (LifecycleObservation) String() string   { return lifecycleObservationRedacted }
func (LifecycleObservation) GoString() string { return lifecycleObservationRedacted }
func (LifecycleObservation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, lifecycleObservationRedacted)
}
func (LifecycleObservation) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// RetirementAttestations captures the seven required explicit operator assertions.
type RetirementAttestations struct {
	RuntimeReload     bool
	RepeatedReadiness bool
	Queues            bool
	EmittedSignatures bool
	ExternalVerify    bool
	Backup            bool
	RollbackAuthority bool
}

// Complete reports whether every retirement assertion is present.
func (a RetirementAttestations) Complete() bool {
	return a.RuntimeReload && a.RepeatedReadiness && a.Queues && a.EmittedSignatures &&
		a.ExternalVerify && a.Backup && a.RollbackAuthority
}

// RetirementEvidence contains only injected current-pointer and overlap facts.
type RetirementEvidence struct {
	CurrentGeneration uint64
	ActivatedAt       time.Time
	ObservedAt        time.Time
	MinimumOverlap    time.Duration
	Attestations      RetirementAttestations
}

// ValidateRetirementEvidence proves exact-current binding and minimum overlap without reading a clock.
func ValidateRetirementEvidence(expectedCurrent uint64, evidence RetirementEvidence) error {
	if expectedCurrent == 0 || evidence.CurrentGeneration != expectedCurrent ||
		evidence.ActivatedAt.IsZero() || evidence.ObservedAt.IsZero() ||
		evidence.ActivatedAt.Location() != time.UTC || evidence.ObservedAt.Location() != time.UTC ||
		evidence.MinimumOverlap <= 0 || evidence.ObservedAt.Before(evidence.ActivatedAt) ||
		evidence.ObservedAt.Sub(evidence.ActivatedAt) < evidence.MinimumOverlap ||
		!evidence.Attestations.Complete() {
		return ErrInvalid
	}
	return nil
}

func (RetirementEvidence) String() string   { return retirementEvidenceRedacted }
func (RetirementEvidence) GoString() string { return retirementEvidenceRedacted }
func (RetirementEvidence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, retirementEvidenceRedacted)
}
func (RetirementEvidence) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// RetirementTransition owns the unique cardinality-neutral binding difference.
type RetirementTransition struct {
	intent      TransitionIntent
	predecessor uint64
	current     uint64
	binding     LifecycleBinding
	retiring    []LifecycleCredential
	active      []LifecycleCredential
	closed      bool
}

// PlanRetirement proves that current differs from its immediate predecessor in exactly one complete binding.
func PlanRetirement(current, predecessor *Generation) (*RetirementTransition, error) {
	if current == nil || predecessor == nil || current.State() != DatasetStateCommitted ||
		predecessor.State() != DatasetStateCommitted || predecessor.Number() == ^uint64(0) ||
		predecessor.Number()+1 != current.Number() {
		return nil, ErrInvalid
	}
	binding, retiring, active, err := uniqueRotatedBinding(current, predecessor)
	if err != nil {
		return nil, err
	}
	return &RetirementTransition{
		intent: TransitionIntentRetirement, predecessor: predecessor.Number(), current: current.Number(),
		binding: binding, retiring: retiring, active: active,
	}, nil
}

// ValidateRotationCandidateIntent proves one fresh normal-rotation successor from complete retained lineage.
func ValidateRotationCandidateIntent(current, candidate *Generation, history LineageHistory) (LifecycleBinding, error) {
	if current == nil || candidate == nil || current.State() != DatasetStateCommitted ||
		(candidate.State() != DatasetStateStaging && candidate.State() != DatasetStateCommitted) ||
		current.Number() == ^uint64(0) || candidate.Number() != current.Number()+1 || !history.Complete {
		return LifecycleBinding{}, ErrInvalid
	}
	clonedHistory, err := history.Clone()
	if err != nil || !clonedHistory.Complete {
		return LifecycleBinding{}, ErrInvalid
	}
	for _, fact := range clonedHistory.Facts {
		if fact.generation > candidate.Number() {
			return LifecycleBinding{}, ErrInvalid
		}
	}
	binding, _, _, err := uniqueRotatedBinding(candidate, current)
	if err != nil {
		return LifecycleBinding{}, err
	}
	if err := validateGenerationLineageProjection(current, clonedHistory, current.Number()); err != nil {
		return LifecycleBinding{}, err
	}
	if err := validateGenerationLineageProjection(candidate, clonedHistory, candidate.Number()); err != nil {
		return LifecycleBinding{}, err
	}
	_, profile, credentials, err := exactActiveBinding(candidate, binding.tenant, binding.domain, binding.use)
	if err != nil || profile.ID() != binding.profileID {
		return LifecycleBinding{}, ErrInvalid
	}
	for _, credential := range credentials {
		for _, fact := range clonedHistory.Facts {
			if fact.generation >= candidate.Number() {
				continue
			}
			if fact.selector == credential.Selector() || fact.handle == credential.HandleID() ||
				fact.algorithm == credential.Algorithm() && bytes.Equal(fact.publicSPKI, credential.publicSPKI) {
				return LifecycleBinding{}, ErrInvalid
			}
		}
	}
	return binding, nil
}

// Intent returns the exact closed retirement intent.
func (t *RetirementTransition) Intent() TransitionIntent {
	if t == nil || t.closed {
		return 0
	}
	return t.intent
}

// PredecessorGeneration returns the exact generation whose DNS records may retire.
func (t *RetirementTransition) PredecessorGeneration() uint64 {
	if t == nil || t.closed {
		return 0
	}
	return t.predecessor
}

// CurrentGeneration returns the exact generation that must remain current.
func (t *RetirementTransition) CurrentGeneration() uint64 {
	if t == nil || t.closed {
		return 0
	}
	return t.current
}

// Binding returns the exact non-key policy tuple.
func (t *RetirementTransition) Binding() LifecycleBinding {
	if t == nil || t.closed {
		return LifecycleBinding{}
	}
	return t.binding
}

// RetiringCredentials returns detached old public DNS expectations.
func (t *RetirementTransition) RetiringCredentials() []LifecycleCredential {
	if t == nil || t.closed {
		return nil
	}
	return cloneLifecycleCredentials(t.retiring)
}

// ActiveCredentials returns detached replacement public DNS expectations.
func (t *RetirementTransition) ActiveCredentials() []LifecycleCredential {
	if t == nil || t.closed {
		return nil
	}
	return cloneLifecycleCredentials(t.active)
}

// Close clears retained public key projections and invalidates the transition owner.
func (t *RetirementTransition) Close() error {
	if t == nil || t.closed {
		return nil
	}
	clearLifecycleCredentials(t.retiring)
	clearLifecycleCredentials(t.active)
	t.retiring = nil
	t.active = nil
	t.binding = LifecycleBinding{}
	t.predecessor = 0
	t.current = 0
	t.intent = 0
	t.closed = true
	return nil
}

func (*RetirementTransition) String() string   { return retirementTransitionRedacted }
func (*RetirementTransition) GoString() string { return retirementTransitionRedacted }
func (*RetirementTransition) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, retirementTransitionRedacted)
}
func (*RetirementTransition) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// ForwardRollbackPlan contains exact protected inputs for one pure forward-only rebase.
type ForwardRollbackPlan struct {
	Current        *Generation
	Source         *Generation
	NextGeneration uint64
	TenantID       string
	Domain         string
	Use            ProfileUse
}

// ForwardRollbackTransition owns one staging candidate with an explicit rollback intent.
type ForwardRollbackTransition struct {
	intent          TransitionIntent
	expectedCurrent uint64
	source          uint64
	binding         LifecycleBinding
	candidate       *Generation
	closed          bool
}

// PlanForwardRollback rebases one retained committed binding above current without moving a pointer.
func PlanForwardRollback(plan ForwardRollbackPlan) (*ForwardRollbackTransition, error) {
	if plan.Current == nil || plan.Source == nil || plan.Current.State() != DatasetStateCommitted ||
		plan.Source.State() != DatasetStateCommitted || plan.Current.Number() == ^uint64(0) ||
		plan.Source.Number() >= plan.Current.Number() || plan.NextGeneration != plan.Current.Number()+1 ||
		ValidateIdentifier(plan.TenantID) != nil || ValidateCanonicalDNSName(plan.Domain) != nil ||
		!plan.Use.SupportsNativeKeyCustody() {
		return nil, ErrInvalid
	}
	currentPolicy, currentProfile, currentCredentials, err := exactActiveBinding(
		plan.Current, plan.TenantID, plan.Domain, plan.Use,
	)
	if err != nil {
		return nil, err
	}
	sourcePolicy, sourceProfile, sourceCredentials, err := exactActiveBinding(
		plan.Source, plan.TenantID, plan.Domain, plan.Use,
	)
	if err != nil || bindingsEqual(plan.Current, currentPolicy, currentProfile, currentCredentials,
		plan.Source, sourcePolicy, sourceProfile, sourceCredentials) {
		return nil, ErrInvalid
	}
	candidate, err := rebaseSourceBinding(plan, currentPolicy, currentProfile, sourcePolicy, sourceProfile)
	if err != nil {
		return nil, err
	}
	return &ForwardRollbackTransition{
		intent: TransitionIntentForwardRollback, expectedCurrent: plan.Current.Number(),
		source: plan.Source.Number(), binding: lifecycleBinding(sourcePolicy), candidate: candidate,
	}, nil
}

// Intent returns the exact closed forward-rollback intent.
func (t *ForwardRollbackTransition) Intent() TransitionIntent {
	if t == nil || t.closed {
		return 0
	}
	return t.intent
}

// ExpectedCurrent returns the exact current pointer required before staging.
func (t *ForwardRollbackTransition) ExpectedCurrent() uint64 {
	if t == nil || t.closed {
		return 0
	}
	return t.expectedCurrent
}

// SourceGeneration returns the retained committed binding source.
func (t *ForwardRollbackTransition) SourceGeneration() uint64 {
	if t == nil || t.closed {
		return 0
	}
	return t.source
}

// CandidateNumber returns the strictly forward staging generation.
func (t *ForwardRollbackTransition) CandidateNumber() uint64 {
	if t == nil || t.closed || t.candidate == nil {
		return 0
	}
	return t.candidate.Number()
}

// Binding returns the exact rebased policy tuple.
func (t *ForwardRollbackTransition) Binding() LifecycleBinding {
	if t == nil || t.closed {
		return LifecycleBinding{}
	}
	return t.binding
}

// Generation returns an independently owned candidate snapshot.
func (t *ForwardRollbackTransition) Generation() (*Generation, error) {
	if t == nil || t.closed || t.candidate == nil {
		return nil, ErrClosed
	}
	return t.candidate.Clone()
}

// Close clears the protected staging candidate and invalidates the transition owner.
func (t *ForwardRollbackTransition) Close() error {
	if t == nil || t.closed {
		return nil
	}
	err := t.candidate.Close()
	t.candidate = nil
	t.binding = LifecycleBinding{}
	t.expectedCurrent = 0
	t.source = 0
	t.intent = 0
	t.closed = true
	return err
}

func (*ForwardRollbackTransition) String() string   { return rollbackTransitionRedacted }
func (*ForwardRollbackTransition) GoString() string { return rollbackTransitionRedacted }
func (*ForwardRollbackTransition) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, rollbackTransitionRedacted)
}
func (*ForwardRollbackTransition) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

func uniqueRotatedBinding(current, predecessor *Generation) (LifecycleBinding, []LifecycleCredential, []LifecycleCredential, error) {
	if len(current.profiles) != len(predecessor.profiles) || len(current.policies) != len(predecessor.policies) ||
		len(current.credentials) != len(predecessor.credentials) || len(current.handles) != len(predecessor.handles) ||
		len(current.materials) != len(predecessor.materials) {
		return LifecycleBinding{}, nil, nil, ErrInvalid
	}
	currentProfiles := profilesByID(current)
	predecessorProfiles := profilesByID(predecessor)
	if len(currentProfiles) != len(current.profiles) || len(predecessorProfiles) != len(predecessor.profiles) {
		return LifecycleBinding{}, nil, nil, ErrInvalid
	}
	for id, previous := range predecessorProfiles {
		next, found := currentProfiles[id]
		if !found || !profilesLogicalEqual(previous, next) {
			return LifecycleBinding{}, nil, nil, ErrInvalid
		}
	}
	if !policiesLogicalEqual(current, predecessor) {
		return LifecycleBinding{}, nil, nil, ErrInvalid
	}

	var changedProfile string
	var retiring, active []LifecycleCredential
	for profileID := range predecessorProfiles {
		oldCredentials := credentialsByAlgorithm(predecessor, profileID)
		newCredentials := credentialsByAlgorithm(current, profileID)
		if len(oldCredentials) == 0 || len(oldCredentials) != len(newCredentials) || len(oldCredentials) > 2 {
			return LifecycleBinding{}, nil, nil, ErrInvalid
		}
		allEqual := true
		allReplaced := true
		for algorithm, oldCredential := range oldCredentials {
			newCredential, found := newCredentials[algorithm]
			if !found {
				return LifecycleBinding{}, nil, nil, ErrInvalid
			}
			oldMaterial, oldFound := materialByHandle(predecessor, oldCredential.HandleID())
			newMaterial, newFound := materialByHandle(current, newCredential.HandleID())
			if !oldFound || !newFound {
				return LifecycleBinding{}, nil, nil, ErrInvalid
			}
			credentialEqual := credentialsLogicalEqual(oldCredential, newCredential)
			materialEqual := materialsLogicalEqual(oldMaterial, newMaterial)
			allEqual = allEqual && credentialEqual && materialEqual
			allReplaced = allReplaced && !credentialEqual && !materialEqual &&
				oldCredential.Selector() != newCredential.Selector() &&
				oldCredential.HandleID() != newCredential.HandleID() &&
				!bytes.Equal(oldCredential.publicSPKI, newCredential.publicSPKI) &&
				materialBindingsEqual(oldMaterial, newMaterial)
		}
		switch {
		case allEqual:
			continue
		case !allReplaced || changedProfile != "":
			return LifecycleBinding{}, nil, nil, ErrInvalid
		default:
			changedProfile = profileID
			retiring = lifecycleCredentials(oldCredentials)
			active = lifecycleCredentials(newCredentials)
		}
	}
	if changedProfile == "" {
		return LifecycleBinding{}, nil, nil, ErrInvalid
	}
	previousPolicy, previousFound := exclusivePolicyForProfile(predecessor, changedProfile)
	currentPolicy, currentFound := exclusivePolicyForProfile(current, changedProfile)
	if !previousFound || !currentFound || !policiesLogicalRecordEqual(previousPolicy, currentPolicy) ||
		previousPolicy.Status() != RecordStatusActive || previousPolicy.Rollout() != RolloutEnforce ||
		!previousPolicy.Use().SupportsNativeKeyCustody() {
		return LifecycleBinding{}, nil, nil, ErrInvalid
	}
	return lifecycleBinding(currentPolicy), retiring, active, nil
}

func validateGenerationLineageProjection(generation *Generation, history LineageHistory, factGeneration uint64) error {
	if generation == nil || generation.Number() != factGeneration {
		return ErrInvalid
	}
	factCount := 0
	for _, fact := range history.Facts {
		if fact.generation == factGeneration {
			factCount++
		}
	}
	if factCount != len(generation.credentials) {
		return ErrInvalid
	}
	for _, credential := range generation.credentials {
		profile, profileFound := generation.ProfileByID(credential.ProfileID())
		policy, policyFound := exclusivePolicyForProfile(generation, credential.ProfileID())
		if !profileFound || !policyFound {
			return ErrInvalid
		}
		matches := 0
		for _, fact := range history.Facts {
			if fact.generation == factGeneration && fact.tenant == policy.TenantID() &&
				fact.domain == profile.SigningDomain() && fact.use == policy.Use() &&
				fact.selector == credential.Selector() && fact.algorithm == credential.Algorithm() &&
				fact.handle == credential.HandleID() && bytes.Equal(fact.publicSPKI, credential.publicSPKI) {
				matches++
			}
		}
		if matches != 1 {
			return ErrInvalid
		}
	}
	return nil
}

func rebaseSourceBinding(plan ForwardRollbackPlan, currentPolicy Policy, currentProfile Profile, sourcePolicy Policy, sourceProfile Profile) (*Generation, error) {
	number := plan.NextGeneration
	handles := make([]Handle, 0, len(plan.Current.handles)-credentialCount(plan.Current, currentProfile.ID())+credentialCount(plan.Source, sourceProfile.ID()))
	profiles := make([]Profile, 0, len(plan.Current.profiles))
	credentials := make([]Credential, 0, len(plan.Current.credentials))
	policies := make([]Policy, 0, len(plan.Current.policies))
	materials := make([]*KeyMaterial, 0, len(plan.Current.materials))
	defer closeKeyMaterials(materials)

	removedHandles := make(map[string]struct{}, 2)
	for _, credential := range plan.Current.credentials {
		if credential.ProfileID() == currentProfile.ID() {
			removedHandles[credential.HandleID()] = struct{}{}
			continue
		}
		credentials = append(credentials, rebaseCredential(credential, number))
	}
	for _, handle := range plan.Current.handles {
		if _, removed := removedHandles[handle.ID()]; !removed {
			handles = append(handles, rebaseHandle(handle, number))
		}
	}
	for _, profile := range plan.Current.profiles {
		if profile.ID() != currentProfile.ID() {
			profiles = append(profiles, rebaseProfile(profile, number))
		}
	}
	for _, policy := range plan.Current.policies {
		if policyKey(policy.TenantID(), policy.SigningDomain(), policy.Use()) !=
			policyKey(currentPolicy.TenantID(), currentPolicy.SigningDomain(), currentPolicy.Use()) {
			policies = append(policies, rebasePolicy(policy, number))
		}
	}
	for _, material := range plan.Current.materials {
		if _, removed := removedHandles[material.HandleID()]; removed {
			continue
		}
		rebased, err := rebaseKeyMaterial(material, number)
		if err != nil {
			return nil, err
		}
		materials = append(materials, rebased)
	}

	profiles = append(profiles, rebaseProfile(sourceProfile, number))
	policies = append(policies, rebasePolicy(sourcePolicy, number))
	for _, credential := range plan.Source.credentials {
		if credential.ProfileID() != sourceProfile.ID() {
			continue
		}
		credentials = append(credentials, rebaseCredential(credential, number))
		handles = append(handles, rebaseHandle(Handle{generation: plan.Source.Number(), id: credential.HandleID()}, number))
		material, found := materialByHandle(plan.Source, credential.HandleID())
		if !found {
			return nil, ErrInvalid
		}
		rebased, err := rebaseKeyMaterial(material, number)
		if err != nil {
			return nil, err
		}
		materials = append(materials, rebased)
	}
	return NewGenerationWithState(number, DatasetStateStaging, handles, profiles, credentials, policies, materials)
}

func bindingsEqual(leftGeneration *Generation, leftPolicy Policy, leftProfile Profile, leftCredentials []Credential,
	rightGeneration *Generation, rightPolicy Policy, rightProfile Profile, rightCredentials []Credential) bool {
	if !profilesLogicalEqual(leftProfile, rightProfile) || !policiesLogicalRecordEqual(leftPolicy, rightPolicy) ||
		len(leftCredentials) != len(rightCredentials) {
		return false
	}
	rightByAlgorithm := credentialsByAlgorithm(rightGeneration, rightProfile.ID())
	for _, leftCredential := range leftCredentials {
		rightCredential, found := rightByAlgorithm[leftCredential.Algorithm()]
		if !found || !credentialsLogicalEqual(leftCredential, rightCredential) {
			return false
		}
		leftMaterial, leftFound := materialByHandle(leftGeneration, leftCredential.HandleID())
		rightMaterial, rightFound := materialByHandle(rightGeneration, rightCredential.HandleID())
		if !leftFound || !rightFound || !materialsLogicalEqual(leftMaterial, rightMaterial) {
			return false
		}
	}
	return true
}

func lifecycleBinding(policy Policy) LifecycleBinding {
	return LifecycleBinding{tenant: policy.TenantID(), domain: policy.SigningDomain(), use: policy.Use(), profileID: policy.ProfileID()}
}

func lifecycleCredentials(input map[Algorithm]Credential) []LifecycleCredential {
	result := make([]LifecycleCredential, 0, len(input))
	for _, credential := range input {
		result = append(result, LifecycleCredential{selector: credential.Selector(), algorithm: credential.Algorithm(), publicSPKI: credential.PublicSPKIDER()})
	}
	slices.SortFunc(result, func(left, right LifecycleCredential) int {
		return algorithmRank(left.algorithm) - algorithmRank(right.algorithm)
	})
	return result
}

func cloneLifecycleCredentials(input []LifecycleCredential) []LifecycleCredential {
	result := make([]LifecycleCredential, len(input))
	for index, credential := range input {
		result[index] = credential
		result[index].publicSPKI = bytes.Clone(credential.publicSPKI)
	}
	return result
}

func clearLifecycleCredentials(input []LifecycleCredential) {
	for index := range input {
		clear(input[index].publicSPKI)
		input[index] = LifecycleCredential{}
	}
}

func profilesByID(generation *Generation) map[string]Profile {
	result := make(map[string]Profile, len(generation.profiles))
	for _, profile := range generation.profiles {
		result[profile.ID()] = profile
	}
	return result
}

func credentialsByAlgorithm(generation *Generation, profileID string) map[Algorithm]Credential {
	result := make(map[Algorithm]Credential, 2)
	for _, credential := range generation.credentials {
		if credential.ProfileID() == profileID {
			result[credential.Algorithm()] = credential
		}
	}
	return result
}

func credentialCount(generation *Generation, profileID string) int {
	return len(credentialsByAlgorithm(generation, profileID))
}

func materialByHandle(generation *Generation, handleID string) (*KeyMaterial, bool) {
	for _, material := range generation.materials {
		if material.HandleID() == handleID {
			return material, true
		}
	}
	return nil, false
}

func exclusivePolicyForProfile(generation *Generation, profileID string) (Policy, bool) {
	var result Policy
	count := 0
	for _, policy := range generation.policies {
		if policy.ProfileID() == profileID {
			result = policy
			count++
		}
	}
	return result, count == 1
}

func profilesLogicalEqual(left, right Profile) bool {
	leftBefore, leftAfter, leftWindow := left.ValidityWindow()
	rightBefore, rightAfter, rightWindow := right.ValidityWindow()
	return left.ID() == right.ID() && left.SigningDomain() == right.SigningDomain() &&
		left.Status() == right.Status() && leftWindow == rightWindow &&
		(!leftWindow || leftBefore.Equal(rightBefore) && leftAfter.Equal(rightAfter))
}

func policiesLogicalEqual(left, right *Generation) bool {
	if len(left.policies) != len(right.policies) {
		return false
	}
	rightByKey := make(map[string]Policy, len(right.policies))
	for _, policy := range right.policies {
		rightByKey[policyKey(policy.TenantID(), policy.SigningDomain(), policy.Use())] = policy
	}
	for _, policy := range left.policies {
		other, found := rightByKey[policyKey(policy.TenantID(), policy.SigningDomain(), policy.Use())]
		if !found || !policiesLogicalRecordEqual(policy, other) {
			return false
		}
	}
	return true
}

func policiesLogicalRecordEqual(left, right Policy) bool {
	return left.TenantID() == right.TenantID() && left.SigningDomain() == right.SigningDomain() &&
		left.Use() == right.Use() && left.ProfileID() == right.ProfileID() && left.Status() == right.Status() &&
		left.Rollout() == right.Rollout() && left.Compatibility() == right.Compatibility() &&
		left.FeedbackRouteID() == right.FeedbackRouteID()
}

func credentialsLogicalEqual(left, right Credential) bool {
	return left.ProfileID() == right.ProfileID() && left.Selector() == right.Selector() &&
		left.Algorithm() == right.Algorithm() && left.HandleID() == right.HandleID() &&
		bytes.Equal(left.publicSPKI, right.publicSPKI)
}

func materialBindingsEqual(left, right *KeyMaterial) bool {
	return left != nil && right != nil && left.TenantID() == right.TenantID() &&
		left.SigningDomain() == right.SigningDomain() && left.Use() == right.Use() &&
		left.Algorithm() == right.Algorithm()
}

func materialsLogicalEqual(left, right *KeyMaterial) bool {
	if !materialBindingsEqual(left, right) || left.HandleID() != right.HandleID() {
		return false
	}
	leftPrivate := left.PrivatePKCS8DER()
	rightPrivate := right.PrivatePKCS8DER()
	defer clear(leftPrivate)
	defer clear(rightPrivate)
	leftPublic := left.PublicSPKIDER()
	rightPublic := right.PublicSPKIDER()
	defer clear(leftPublic)
	defer clear(rightPublic)
	return bytes.Equal(leftPrivate, rightPrivate) && bytes.Equal(leftPublic, rightPublic)
}
