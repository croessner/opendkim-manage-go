package dkim2model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

const generationRedacted = "dkim2model.Generation{redacted}"

const (
	maxProfiles    = 1024
	maxCredentials = 2048
	maxHandles     = 2048
	maxPolicies    = 4096
	maxRecords     = 9216
)

// Generation owns one complete immutable all-domain DKIM2 snapshot.
type Generation struct {
	number      uint64
	state       DatasetState
	handles     []Handle
	profiles    []Profile
	credentials []Credential
	policies    []Policy
	materials   []*KeyMaterial
}

// NewGeneration constructs one complete committed immutable generation.
func NewGeneration(
	number uint64,
	handles []Handle,
	profiles []Profile,
	credentials []Credential,
	policies []Policy,
	materials []*KeyMaterial,
) (*Generation, error) {
	return NewGenerationWithState(
		number, DatasetStateCommitted, handles, profiles, credentials, policies, materials,
	)
}

// NewGenerationWithState constructs one complete generation with an explicit publication state.
func NewGenerationWithState(
	number uint64,
	state DatasetState,
	handles []Handle,
	profiles []Profile,
	credentials []Credential,
	policies []Policy,
	materials []*KeyMaterial,
) (*Generation, error) {
	if number == 0 || !state.Known() || len(handles) == 0 || len(profiles) == 0 ||
		len(credentials) == 0 || len(policies) == 0 || len(materials) == 0 ||
		len(handles) > maxHandles || len(profiles) > maxProfiles ||
		len(credentials) > maxCredentials || len(policies) > maxPolicies ||
		len(materials) > maxHandles ||
		len(handles)+len(profiles)+len(credentials)+len(policies) > maxRecords {
		return nil, ErrInvalid
	}
	result := &Generation{
		number:      number,
		state:       state,
		handles:     append([]Handle(nil), handles...),
		profiles:    append([]Profile(nil), profiles...),
		credentials: cloneCredentials(credentials),
		policies:    append([]Policy(nil), policies...),
	}
	for _, material := range materials {
		if material == nil {
			_ = result.Close()
			return nil, ErrInvalid
		}
		clone, err := material.Clone()
		if err != nil {
			_ = result.Close()
			return nil, ErrInvalid
		}
		result.materials = append(result.materials, clone)
	}
	result.sortRecords()
	if err := result.validate(); err != nil {
		_ = result.Close()
		return nil, err
	}
	return result, nil
}

// validate enforces complete relationships, closed values, and global uniqueness.
func (g *Generation) validate() error {
	if g == nil || g.number == 0 || !g.state.Known() {
		return ErrInvalid
	}
	handles := make(map[string]struct{}, len(g.handles))
	for _, handle := range g.handles {
		if handle.Generation() != g.number || ValidateIdentifier(handle.ID()) != nil {
			return ErrInvalid
		}
		if _, duplicate := handles[handle.ID()]; duplicate {
			return ErrInvalid
		}
		handles[handle.ID()] = struct{}{}
	}

	profiles := make(map[string]Profile, len(g.profiles))
	for _, profile := range g.profiles {
		if profile.Generation() != g.number {
			return ErrInvalid
		}
		if _, duplicate := profiles[profile.ID()]; duplicate {
			return ErrInvalid
		}
		profiles[profile.ID()] = profile
	}

	credentialByHandle := make(map[string]Credential, len(g.credentials))
	selectors := make(map[string]struct{}, len(g.credentials))
	profileAlgorithms := make(map[string]map[Algorithm]struct{}, len(g.profiles))
	profileCredentialCount := make(map[string]int, len(g.profiles))
	for _, credential := range g.credentials {
		if credential.Generation() != g.number || !credential.Algorithm().Known() {
			return ErrInvalid
		}
		profile, found := profiles[credential.ProfileID()]
		if !found || ValidateDomainSelector(profile.SigningDomain(), credential.Selector()) != nil {
			return ErrInvalid
		}
		if _, found := handles[credential.HandleID()]; !found {
			return ErrInvalid
		}
		if _, duplicate := credentialByHandle[credential.HandleID()]; duplicate {
			return ErrInvalid
		}
		credentialByHandle[credential.HandleID()] = credential
		if _, duplicate := selectors[credential.Selector()]; duplicate {
			return ErrInvalid
		}
		selectors[credential.Selector()] = struct{}{}
		algorithms := profileAlgorithms[credential.ProfileID()]
		if algorithms == nil {
			algorithms = make(map[Algorithm]struct{}, 2)
			profileAlgorithms[credential.ProfileID()] = algorithms
		}
		if _, duplicate := algorithms[credential.Algorithm()]; duplicate {
			return ErrInvalid
		}
		algorithms[credential.Algorithm()] = struct{}{}
		profileCredentialCount[credential.ProfileID()]++
		if profileCredentialCount[credential.ProfileID()] > 2 {
			return ErrInvalid
		}
	}
	for profileID := range profiles {
		if profileCredentialCount[profileID] == 0 {
			return ErrInvalid
		}
	}

	policies := make(map[string]Policy, len(g.policies))
	for _, policy := range g.policies {
		profile, found := profiles[policy.ProfileID()]
		if policy.Generation() != g.number || !found ||
			profile.SigningDomain() != policy.SigningDomain() {
			return ErrInvalid
		}
		if (policy.Status() == RecordStatusActive || policy.Rollout() == RolloutEnforce) &&
			profile.Status() != RecordStatusActive {
			return ErrInvalid
		}
		if policy.Rollout() == RolloutEnforce && policy.Status() != RecordStatusActive {
			return ErrInvalid
		}
		key := policyKey(policy.TenantID(), policy.SigningDomain(), policy.Use())
		if _, duplicate := policies[key]; duplicate {
			return ErrInvalid
		}
		policies[key] = policy
	}

	materialByHandle := make(map[string]*KeyMaterial, len(g.materials))
	selection := make(map[string]struct{}, len(g.materials))
	for _, material := range g.materials {
		if material == nil || material.Generation() != g.number ||
			!material.Algorithm().Known() {
			return ErrInvalid
		}
		if _, found := handles[material.HandleID()]; !found {
			return ErrInvalid
		}
		if _, duplicate := materialByHandle[material.HandleID()]; duplicate {
			return ErrInvalid
		}
		materialByHandle[material.HandleID()] = material
		selectionKey := policyKey(
			material.TenantID(), material.SigningDomain(), material.Use(),
		) + "\x00" + string(material.Algorithm())
		if _, duplicate := selection[selectionKey]; duplicate {
			return ErrInvalid
		}
		selection[selectionKey] = struct{}{}
		policy, found := policies[policyKey(material.TenantID(), material.SigningDomain(), material.Use())]
		credential, credentialFound := credentialByHandle[material.HandleID()]
		if !found || !credentialFound || policy.ProfileID() != credential.ProfileID() ||
			material.Algorithm() != credential.Algorithm() ||
			!bytes.Equal(material.PublicSPKIDER(), credential.PublicSPKIDER()) {
			return ErrInvalid
		}
	}
	if len(materialByHandle) != len(credentialByHandle) || len(handles) != len(credentialByHandle) {
		return ErrInvalid
	}
	return nil
}

// Number returns the nonzero immutable generation number.
func (g *Generation) Number() uint64 {
	if g == nil {
		return 0
	}
	return g.number
}

// State returns the exact publication state.
func (g *Generation) State() DatasetState {
	if g == nil {
		return ""
	}
	return g.state
}

// Handles returns detached immutable handle declarations.
func (g *Generation) Handles() []Handle {
	if g == nil {
		return nil
	}
	return append([]Handle(nil), g.handles...)
}

// Profiles returns detached immutable profile records.
func (g *Generation) Profiles() []Profile {
	if g == nil {
		return nil
	}
	return append([]Profile(nil), g.profiles...)
}

// Credentials returns detached immutable credential records.
func (g *Generation) Credentials() []Credential {
	if g == nil {
		return nil
	}
	return cloneCredentials(g.credentials)
}

// Policies returns detached immutable policy records.
func (g *Generation) Policies() []Policy {
	if g == nil {
		return nil
	}
	return append([]Policy(nil), g.policies...)
}

// KeyMaterials returns independently owned protected key-material records.
func (g *Generation) KeyMaterials() []*KeyMaterial {
	if g == nil {
		return nil
	}
	result := make([]*KeyMaterial, 0, len(g.materials))
	for _, material := range g.materials {
		clone, err := material.Clone()
		if err != nil {
			closeKeyMaterials(result)
			return nil
		}
		result = append(result, clone)
	}
	return result
}

// ProfileByID resolves one exact profile without fallback.
func (g *Generation) ProfileByID(id string) (Profile, bool) {
	if g == nil {
		return Profile{}, false
	}
	for _, profile := range g.profiles {
		if profile.ID() == id {
			return profile, true
		}
	}
	return Profile{}, false
}

// ProfileByDomain resolves one domain only when exactly one profile exists.
func (g *Generation) ProfileByDomain(domain string) (Profile, bool) {
	if g == nil {
		return Profile{}, false
	}
	var result Profile
	count := 0
	for _, profile := range g.profiles {
		if profile.SigningDomain() == domain {
			result = profile
			count++
		}
	}
	return result, count == 1
}

// CredentialByDomainSelector resolves one exact domain and selector without fallback.
func (g *Generation) CredentialByDomainSelector(domain, selector string) (Credential, bool) {
	if g == nil {
		return Credential{}, false
	}
	var result Credential
	count := 0
	for _, credential := range g.credentials {
		profile, found := g.ProfileByID(credential.ProfileID())
		if found && profile.SigningDomain() == domain && credential.Selector() == selector {
			result = credential
			count++
		}
	}
	return result, count == 1
}

// KeyMaterialByHandle returns one independently owned exact key-material record.
func (g *Generation) KeyMaterialByHandle(handleID string) (*KeyMaterial, bool) {
	if g == nil {
		return nil, false
	}
	for _, material := range g.materials {
		if material.HandleID() == handleID {
			clone, err := material.Clone()
			return clone, err == nil
		}
	}
	return nil, false
}

// Clone returns one independently owned complete snapshot.
func (g *Generation) Clone() (*Generation, error) {
	if g == nil {
		return nil, ErrInvalid
	}
	return NewGenerationWithState(
		g.number, g.state, g.handles, g.profiles, g.credentials, g.policies, g.materials,
	)
}

// Equivalent compares exact canonical records without exposing private key bytes.
func (g *Generation) Equivalent(other *Generation) bool {
	if g == nil || other == nil || g.number != other.number || g.state != other.state ||
		len(g.handles) != len(other.handles) || len(g.profiles) != len(other.profiles) ||
		len(g.credentials) != len(other.credentials) || len(g.policies) != len(other.policies) ||
		len(g.materials) != len(other.materials) {
		return false
	}
	for index := range g.handles {
		if g.handles[index] != other.handles[index] {
			return false
		}
	}
	for index := range g.profiles {
		if g.profiles[index] != other.profiles[index] {
			return false
		}
	}
	for index := range g.credentials {
		left, right := g.credentials[index], other.credentials[index]
		if left.Generation() != right.Generation() || left.ProfileID() != right.ProfileID() ||
			left.Selector() != right.Selector() || left.Algorithm() != right.Algorithm() ||
			left.HandleID() != right.HandleID() ||
			!bytes.Equal(left.PublicSPKIDER(), right.PublicSPKIDER()) {
			return false
		}
	}
	for index := range g.policies {
		if g.policies[index] != other.policies[index] {
			return false
		}
	}
	for index := range g.materials {
		if !g.materials[index].Equivalent(other.materials[index]) {
			return false
		}
	}
	return true
}

// NextBuilder clones this snapshot into one strictly higher candidate generation.
func (g *Generation) NextBuilder(number uint64, state DatasetState) (*Builder, error) {
	if g == nil || number <= g.number || !state.Known() {
		return nil, ErrInvalid
	}
	builder := &Builder{number: number, state: state}
	for _, handle := range g.handles {
		builder.handles = append(builder.handles, rebaseHandle(handle, number))
	}
	for _, profile := range g.profiles {
		builder.profiles = append(builder.profiles, rebaseProfile(profile, number))
	}
	for _, credential := range g.credentials {
		builder.credentials = append(builder.credentials, rebaseCredential(credential, number))
	}
	for _, policy := range g.policies {
		builder.policies = append(builder.policies, rebasePolicy(policy, number))
	}
	for _, material := range g.materials {
		rebased, err := rebaseKeyMaterial(material, number)
		if err != nil {
			_ = builder.Close()
			return nil, err
		}
		builder.materials = append(builder.materials, rebased)
	}
	return builder, nil
}

// Close clears every retained private key and invalidates this generation owner.
func (g *Generation) Close() error {
	if g == nil {
		return nil
	}
	closeKeyMaterials(g.materials)
	g.number = 0
	g.state = ""
	g.handles = nil
	g.profiles = nil
	g.credentials = nil
	g.policies = nil
	g.materials = nil
	return nil
}

// String returns a constant protected generation summary.
func (*Generation) String() string { return generationRedacted }

// GoString returns a constant protected generation representation.
func (*Generation) GoString() string { return generationRedacted }

// Format prevents formatting verbs from traversing protected generation state.
func (*Generation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, generationRedacted)
}

// MarshalJSON emits an empty object without identities or protected records.
func (*Generation) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// Builder owns a detached mutable next-generation candidate.
type Builder struct {
	number      uint64
	state       DatasetState
	handles     []Handle
	profiles    []Profile
	credentials []Credential
	policies    []Policy
	materials   []*KeyMaterial
}

// NewBuilder creates an empty owner for the first complete generation.
func NewBuilder(number uint64, state DatasetState) (*Builder, error) {
	if number == 0 || !state.Known() {
		return nil, ErrInvalid
	}
	return &Builder{number: number, state: state}, nil
}

// Number returns the candidate generation number.
func (b *Builder) Number() uint64 {
	if b == nil {
		return 0
	}
	return b.number
}

// AddProfileWithKeys appends one complete profile, policy, credentials, and key material.
func (b *Builder) AddProfileWithKeys(
	profile Profile,
	credentials []Credential,
	policy Policy,
	materials []*KeyMaterial,
) error {
	if err := b.AddProfile(profile, credentials, materials); err != nil {
		return err
	}
	if policy.Generation() != b.number || policy.ProfileID() != profile.ID() {
		return ErrInvalid
	}
	b.policies = append(b.policies, policy)
	return nil
}

// AddProfile appends one profile and its credentials and key material without a policy.
func (b *Builder) AddProfile(
	profile Profile,
	credentials []Credential,
	materials []*KeyMaterial,
) error {
	if b == nil || b.number == 0 || profile.Generation() != b.number ||
		len(credentials) == 0 || len(credentials) != len(materials) {
		return ErrInvalid
	}
	for _, credential := range credentials {
		if credential.Generation() != b.number || credential.ProfileID() != profile.ID() {
			return ErrInvalid
		}
	}
	cloned := make([]*KeyMaterial, 0, len(materials))
	for _, material := range materials {
		if material == nil || material.Generation() != b.number {
			closeKeyMaterials(cloned)
			return ErrInvalid
		}
		clone, err := material.Clone()
		if err != nil {
			closeKeyMaterials(cloned)
			return err
		}
		cloned = append(cloned, clone)
	}
	b.profiles = append(b.profiles, profile)
	b.credentials = append(b.credentials, cloneCredentials(credentials)...)
	for _, material := range cloned {
		handle, err := NewHandle(b.number, material.HandleID())
		if err != nil {
			closeKeyMaterials(cloned)
			return err
		}
		b.handles = append(b.handles, handle)
	}
	b.materials = append(b.materials, cloned...)
	return nil
}

// ReplaceProfile replaces one exact profile record without changing its credentials.
func (b *Builder) ReplaceProfile(profile Profile) error {
	if b == nil || profile.Generation() != b.number {
		return ErrInvalid
	}
	for index := range b.profiles {
		if b.profiles[index].ID() == profile.ID() {
			b.profiles[index] = profile
			return nil
		}
	}
	return ErrInvalid
}

// ReplaceProfileKeys atomically replaces every credential, handle, and key owner for one profile.
func (b *Builder) ReplaceProfileKeys(
	profileID string,
	credentials []Credential,
	materials []*KeyMaterial,
) error {
	if b == nil || b.number == 0 || ValidateIdentifier(profileID) != nil ||
		len(credentials) == 0 || len(credentials) != len(materials) {
		return ErrInvalid
	}
	profileFound := false
	for _, profile := range b.profiles {
		if profile.ID() == profileID {
			profileFound = true
			break
		}
	}
	if !profileFound {
		return ErrInvalid
	}
	owned := make([]*KeyMaterial, 0, len(materials))
	newHandles := make([]Handle, 0, len(materials))
	for index, credential := range credentials {
		material := materials[index]
		if credential.Generation() != b.number || credential.ProfileID() != profileID ||
			material == nil || material.Generation() != b.number ||
			credential.HandleID() != material.HandleID() ||
			credential.Algorithm() != material.Algorithm() ||
			!bytes.Equal(credential.PublicSPKIDER(), material.PublicSPKIDER()) {
			closeKeyMaterials(owned)
			return ErrInvalid
		}
		clone, err := material.Clone()
		if err != nil {
			closeKeyMaterials(owned)
			return err
		}
		handle, err := NewHandle(b.number, material.HandleID())
		if err != nil {
			_ = clone.Close()
			closeKeyMaterials(owned)
			return err
		}
		owned = append(owned, clone)
		newHandles = append(newHandles, handle)
	}

	removedHandles := make(map[string]struct{}, 2)
	keptCredentials := b.credentials[:0]
	for _, credential := range b.credentials {
		if credential.ProfileID() == profileID {
			removedHandles[credential.HandleID()] = struct{}{}
			continue
		}
		keptCredentials = append(keptCredentials, credential)
	}
	if len(removedHandles) == 0 {
		closeKeyMaterials(owned)
		return ErrInvalid
	}
	keptHandles := b.handles[:0]
	for _, handle := range b.handles {
		if _, remove := removedHandles[handle.ID()]; !remove {
			keptHandles = append(keptHandles, handle)
		}
	}
	keptMaterials := b.materials[:0]
	for _, material := range b.materials {
		if _, remove := removedHandles[material.HandleID()]; remove {
			_ = material.Close()
			continue
		}
		keptMaterials = append(keptMaterials, material)
	}
	b.credentials = append(keptCredentials, cloneCredentials(credentials)...)
	b.handles = append(keptHandles, newHandles...)
	b.materials = append(keptMaterials, owned...)
	return nil
}

// UpsertPolicy replaces one exact tenant/domain/use binding or appends it.
func (b *Builder) UpsertPolicy(policy Policy) error {
	if b == nil || policy.Generation() != b.number {
		return ErrInvalid
	}
	key := policyKey(policy.TenantID(), policy.SigningDomain(), policy.Use())
	for index := range b.policies {
		current := b.policies[index]
		if policyKey(current.TenantID(), current.SigningDomain(), current.Use()) == key {
			b.policies[index] = policy
			return nil
		}
	}
	b.policies = append(b.policies, policy)
	return nil
}

// Build validates and returns one independently owned complete candidate.
func (b *Builder) Build() (*Generation, error) {
	if b == nil {
		return nil, ErrInvalid
	}
	return NewGenerationWithState(
		b.number, b.state, b.handles, b.profiles, b.credentials, b.policies, b.materials,
	)
}

// Close clears all protected candidate material and invalidates the builder.
func (b *Builder) Close() error {
	if b == nil {
		return nil
	}
	closeKeyMaterials(b.materials)
	b.number = 0
	b.state = ""
	b.handles = nil
	b.profiles = nil
	b.credentials = nil
	b.policies = nil
	b.materials = nil
	return nil
}

// sortRecords establishes canonical order for deterministic publication and comparison.
func (g *Generation) sortRecords() {
	slices.SortFunc(g.handles, func(left, right Handle) int {
		return stringsCompare(left.ID(), right.ID())
	})
	slices.SortFunc(g.profiles, func(left, right Profile) int {
		return stringsCompare(left.ID(), right.ID())
	})
	slices.SortFunc(g.credentials, func(left, right Credential) int {
		if compared := stringsCompare(left.ProfileID(), right.ProfileID()); compared != 0 {
			return compared
		}
		if compared := algorithmRank(left.Algorithm()) - algorithmRank(right.Algorithm()); compared != 0 {
			return compared
		}
		return stringsCompare(left.Selector(), right.Selector())
	})
	slices.SortFunc(g.policies, func(left, right Policy) int {
		return stringsCompare(
			policyKey(left.TenantID(), left.SigningDomain(), left.Use()),
			policyKey(right.TenantID(), right.SigningDomain(), right.Use()),
		)
	})
	slices.SortFunc(g.materials, func(left, right *KeyMaterial) int {
		return stringsCompare(left.HandleID(), right.HandleID())
	})
}

// cloneCredentials detaches every public SPKI buffer.
func cloneCredentials(input []Credential) []Credential {
	result := make([]Credential, len(input))
	for index, credential := range input {
		result[index] = cloneCredential(credential)
	}
	return result
}

// closeKeyMaterials clears every protected owner in one collection.
func closeKeyMaterials(materials []*KeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}

// policyKey constructs one internal exact tuple key.
func policyKey(tenant, domain string, use ProfileUse) string {
	return tenant + "\x00" + domain + "\x00" + string(use)
}

// algorithmRank returns the canonical RSA-before-Ed25519 order.
func algorithmRank(algorithm Algorithm) int {
	if algorithm == AlgorithmRSASHA256 {
		return 0
	}
	return 1
}

// stringsCompare avoids locale or normalization semantics for canonical ASCII values.
func stringsCompare(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
