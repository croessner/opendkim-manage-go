package app

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

// lifecycleBinding carries the complete non-key policy identity through orchestration.
type lifecycleBinding struct {
	tenant string
	domain string
	use    dkim2model.ProfileUse
}

func (b lifecycleBinding) valid() bool {
	return dkim2model.ValidateIdentifier(b.tenant) == nil &&
		dkim2model.ValidateCanonicalDNSName(b.domain) == nil && b.use.SupportsNativeKeyCustody()
}

func configuredLifecycleBinding(cfgTenant, domain, cfgUse string) lifecycleBinding {
	return lifecycleBinding{tenant: cfgTenant, domain: domain, use: dkim2model.ProfileUse(cfgUse)}
}

func modelLifecycleBinding(binding dkim2model.LifecycleBinding) lifecycleBinding {
	return lifecycleBinding{tenant: binding.TenantID(), domain: binding.Domain(), use: binding.Use()}
}

// rotate executes one bounded manual native rotation or exact stored-candidate resume.
func (m *DKIM2Manager) rotate(ctx context.Context, result *RunResult) error {
	if m.rotationRepository == nil || result == nil {
		return errors.New("DKIM2 rotation repository is unavailable")
	}
	domain, err := exactCanonical(m.opts.Domains[0], dkim2model.CanonicalDomain)
	if err != nil {
		return errors.New("DKIM2 rotation domain is invalid")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("DKIM2 rotation deadline expired")
	}
	binding := configuredLifecycleBinding(m.cfg.DKIM2.TenantID, domain, m.cfg.DKIM2.ProfileUse)
	if !binding.valid() {
		return errors.New("DKIM2 rotation binding is invalid")
	}

	var prepared *dkim2store.PreparedGeneration
	if m.opts.ResumeGenerationSet {
		prepared, err = m.rotationRepository.LoadPending(ctx, m.opts.ResumeGeneration, m.cfg.DKIM2.HistoryLimit)
		if err != nil {
			return errors.New("DKIM2 stored rotation candidate cannot be resumed safely")
		}
		predecessor, loadErr := m.rotationRepository.LoadRetainedGeneration(ctx, prepared.ExpectedCurrent(), m.cfg.DKIM2.HistoryLimit)
		if loadErr != nil {
			_ = prepared.Close()
			return errors.New("DKIM2 stored rotation predecessor cannot be loaded safely")
		}
		history, historyErr := m.rotationRepository.LoadRetainedHistory(ctx, m.cfg.DKIM2.HistoryLimit)
		if historyErr != nil {
			_ = predecessor.Close()
			_ = prepared.Close()
			return errors.New("DKIM2 stored rotation history cannot be loaded safely")
		}
		intentBinding, intentErr := preparedRotationBinding(predecessor, prepared, history)
		_ = predecessor.Close()
		if intentErr != nil || intentBinding != binding {
			_ = prepared.Close()
			return errors.New("DKIM2 stored candidate is not a fresh normal rotation for the requested binding")
		}
		if err := m.validateResumeAlgorithmSet(prepared, binding); err != nil {
			_ = prepared.Close()
			return err
		}
	} else {
		prepared, err = m.prepareRotation(ctx, binding, result, 0)
		if err != nil || m.opts.DryRun {
			return err
		}
	}
	if prepared == nil {
		return errors.New("DKIM2 prepared rotation candidate is unavailable")
	}
	return m.continuePreparedRotation(ctx, result, prepared, binding, m.opts.DryRun, m.opts.PrepareOnly)
}

// continuePreparedRotation publishes and activates one exact repository-owned candidate.
func (m *DKIM2Manager) continuePreparedRotation(
	ctx context.Context,
	result *RunResult,
	prepared *dkim2store.PreparedGeneration,
	binding lifecycleBinding,
	dryRun bool,
	prepareOnly bool,
) error {
	if prepared == nil || result == nil || !binding.valid() {
		return errors.New("DKIM2 prepared rotation candidate is unavailable")
	}
	result.DKIM2Outcome = DKIM2OutcomeStaged
	defer func() { _ = prepared.Close() }()

	stored, err := prepared.Generation()
	if err != nil {
		return errors.New("DKIM2 stored rotation candidate is malformed")
	}
	defer func() { _ = stored.Close() }()
	records, err := rotationExpectedRecords(stored, binding.tenant, binding.domain, binding.use)
	if err != nil {
		return errors.New("DKIM2 stored rotation candidate does not match the requested binding")
	}
	if prepared.ObservedCurrent() == prepared.CandidateNumber() {
		if stored.State() != dkim2model.DatasetStateCommitted {
			return errors.New("DKIM2 activated rotation candidate is malformed")
		}
		return m.reportRotation(result, DKIM2OutcomeAlreadyActivated)
	}
	if dryRun {
		return m.reportRotationDryRun(result, true)
	}
	if prepareOnly {
		return m.reportRotation(result, DKIM2OutcomeStaged)
	}

	if m.newRotationPublisher == nil || m.newRotationProof == nil {
		return errors.New("DKIM2 DNS lifecycle dependencies are unavailable")
	}
	publisher, err := m.newRotationPublisher(m.cfg)
	if err != nil || publisher == nil {
		return errors.New("DKIM2 DNS publisher is unavailable")
	}
	proof, err := m.newRotationProof(m.cfg)
	if err != nil || proof == nil {
		return errors.New("DKIM2 DNS proof client is unavailable")
	}
	zone := binding.domain + "."
	for _, record := range records {
		if _, err := publisher.PublishIfAbsent(ctx, zone, record); err != nil {
			return errors.New("DKIM2 DNS publication is conflicting or uncertain")
		}
	}
	if err := proof.ProveAll(ctx, records); err != nil {
		return errors.New("DKIM2 DNS proof is pending, conflicting, or uncertain")
	}

	refreshed, err := m.rotationRepository.LoadPending(ctx, prepared.CandidateNumber(), m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return errors.New("DKIM2 candidate readback before activation is uncertain")
	}
	defer func() { _ = refreshed.Close() }()
	refreshedGeneration, err := refreshed.Generation()
	if err != nil {
		return errors.New("DKIM2 candidate readback before activation is malformed")
	}
	if !stored.Equivalent(refreshedGeneration) || refreshed.ExpectedCurrent() != prepared.ExpectedCurrent() ||
		refreshed.ObservedCurrent() != prepared.ExpectedCurrent() {
		_ = refreshedGeneration.Close()
		return errors.New("DKIM2 candidate or current changed before activation")
	}
	refreshedRecords, err := rotationExpectedRecords(refreshedGeneration, binding.tenant, binding.domain, binding.use)
	_ = refreshedGeneration.Close()
	if err != nil || !sameExpectedRecords(records, refreshedRecords) {
		return errors.New("DKIM2 candidate DNS expectation changed before activation")
	}
	if err := proof.ProveAll(ctx, refreshedRecords); err != nil {
		return errors.New("DKIM2 final DNS proof is pending, conflicting, or uncertain")
	}

	if err := m.rotationRepository.CommitAndSwitch(ctx, prepared.CandidateNumber(), m.cfg.DKIM2.HistoryLimit); err != nil {
		reconciled, readErr := m.rotationRepository.LoadPending(ctx, prepared.CandidateNumber(), m.cfg.DKIM2.HistoryLimit)
		if readErr != nil {
			return errors.New("DKIM2 activation outcome is uncertain")
		}
		defer func() { _ = reconciled.Close() }()
		if reconciled.ObservedCurrent() != prepared.CandidateNumber() {
			return errors.New("DKIM2 activation did not close and requires explicit resume")
		}
	}
	final, err := m.rotationRepository.LoadPending(ctx, prepared.CandidateNumber(), m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return errors.New("DKIM2 activation readback is uncertain")
	}
	defer func() { _ = final.Close() }()
	finalGeneration, err := final.Generation()
	if err != nil {
		return errors.New("DKIM2 activation readback is malformed")
	}
	defer func() { _ = finalGeneration.Close() }()
	if final.ObservedCurrent() != prepared.CandidateNumber() || final.ExpectedCurrent() != prepared.ExpectedCurrent() ||
		finalGeneration.State() != dkim2model.DatasetStateCommitted || !generationEquivalentExceptState(stored, finalGeneration) {
		return errors.New("DKIM2 activation readback did not prove completion")
	}
	finalRecords, err := rotationExpectedRecords(finalGeneration, binding.tenant, binding.domain, binding.use)
	if err != nil || !sameExpectedRecords(records, finalRecords) {
		return errors.New("DKIM2 activation readback changed the DNS expectation")
	}
	return m.reportRotation(result, DKIM2OutcomeActivated)
}

// prepareRotation builds and stages exactly one strict current-generation successor.
func (m *DKIM2Manager) prepareRotation(ctx context.Context, binding lifecycleBinding, result *RunResult, expectedCurrent uint64) (*dkim2store.PreparedGeneration, error) {
	if !binding.valid() {
		return nil, errors.New("DKIM2 rotation binding is invalid")
	}
	current, err := m.rotationRepository.LoadCurrent(ctx)
	if err != nil {
		return nil, errors.New("DKIM2 current generation cannot be loaded safely")
	}
	if current == nil {
		return nil, errors.New("DKIM2 rotation requires an existing current generation")
	}
	defer func() { _ = current.Close() }()
	if expectedCurrent != 0 && current.Number() != expectedCurrent {
		return nil, errors.New("DKIM2 current generation changed after eligibility selection")
	}
	history, err := m.loadMutationHistory(ctx, current)
	if err != nil {
		return nil, errors.New("DKIM2 retained history does not permit rotation")
	}
	if current.Number() == ^uint64(0) {
		return nil, errors.New("DKIM2 generation counter is exhausted")
	}
	var algorithms []dkim2model.Algorithm
	if m.opts.KeyType != "" {
		algorithms, err = m.algorithms()
		if err != nil {
			return nil, errors.New("DKIM2 rotation algorithm override is invalid")
		}
	}
	candidate, err := dkim2model.PlanRotation(dkim2model.RotationPlan{
		Current: current, NextGeneration: current.Number() + 1,
		TenantID: binding.tenant, Domain: binding.domain, Use: binding.use,
		Algorithms: algorithms, RSABits: m.opts.Size, Random: m.random, History: history,
	})
	if err != nil {
		return nil, errors.New("DKIM2 rotation candidate cannot be built safely")
	}
	defer func() { _ = candidate.Close() }()
	if m.opts.DryRun {
		return nil, m.reportRotationDryRun(result, false)
	}
	prepared, err := m.rotationRepository.Stage(ctx, candidate, m.cfg.DKIM2.HistoryLimit)
	if err == nil {
		if !preparedMatchesCandidate(prepared, candidate) {
			if prepared != nil {
				_ = prepared.Close()
			}
			return nil, errors.New("DKIM2 staging readback does not match the planned candidate")
		}
		return prepared, nil
	}
	// A failed response is never retried. Exact LDAP readback alone may prove that staging completed.
	prepared, readErr := m.rotationRepository.LoadPending(ctx, candidate.Number(), m.cfg.DKIM2.HistoryLimit)
	if readErr != nil {
		return nil, errors.New("DKIM2 staging outcome is uncertain")
	}
	if !preparedMatchesCandidate(prepared, candidate) {
		_ = prepared.Close()
		return nil, errors.New("DKIM2 staging readback does not match the planned candidate")
	}
	return prepared, nil
}

// validateResumeAlgorithmSet rejects a CLI override that differs from stored protected intent.
func (m *DKIM2Manager) validateResumeAlgorithmSet(prepared *dkim2store.PreparedGeneration, binding lifecycleBinding) error {
	if m.opts.KeyType == "" {
		return nil
	}
	candidate, err := prepared.Generation()
	if err != nil {
		return errors.New("DKIM2 stored rotation candidate is malformed")
	}
	defer func() { _ = candidate.Close() }()
	policy, found := exactPolicy(candidate, binding.tenant, binding.domain, binding.use)
	if !found {
		return errors.New("DKIM2 stored rotation candidate does not match the requested binding")
	}
	credentials := credentialsForProfile(candidate, policy.ProfileID())
	want, err := m.algorithms()
	if err != nil || len(credentials) != len(want) {
		return errors.New("--keytype does not match the stored DKIM2 candidate algorithm set")
	}
	seen := make(map[dkim2model.Algorithm]struct{}, len(credentials))
	for _, credential := range credentials {
		seen[credential.Algorithm()] = struct{}{}
	}
	for _, algorithm := range want {
		if _, found := seen[algorithm]; !found {
			return errors.New("--keytype does not match the stored DKIM2 candidate algorithm set")
		}
	}
	return nil
}

// preparedMatchesCandidate rejects adoption of a concurrent foreign successor after a lost response.
func preparedMatchesCandidate(prepared *dkim2store.PreparedGeneration, candidate *dkim2model.Generation) bool {
	if prepared == nil || candidate == nil || prepared.CandidateNumber() != candidate.Number() ||
		prepared.ExpectedCurrent() != candidate.Number()-1 || prepared.ObservedCurrent() != prepared.ExpectedCurrent() {
		return false
	}
	readback, err := prepared.Generation()
	if err != nil {
		return false
	}
	defer func() { _ = readback.Close() }()
	return candidate.Equivalent(readback)
}

// rotationExpectedRecords derives public DNS expectations only from one exact candidate snapshot.
func rotationExpectedRecords(candidate *dkim2model.Generation, tenant, domain string, use dkim2model.ProfileUse) ([]dnsupdate.ExpectedTXT, error) {
	if candidate == nil || (candidate.State() != dkim2model.DatasetStateStaging && candidate.State() != dkim2model.DatasetStateCommitted) {
		return nil, dkim2model.ErrInvalid
	}
	policy, found := exactPolicy(candidate, tenant, domain, use)
	if !found || policy.Status() != dkim2model.RecordStatusActive {
		return nil, dkim2model.ErrInvalid
	}
	profile, found := candidate.ProfileByID(policy.ProfileID())
	if !found || profile.Status() != dkim2model.RecordStatusActive || profile.SigningDomain() != domain {
		return nil, dkim2model.ErrInvalid
	}
	credentials := credentialsForProfile(candidate, profile.ID())
	if len(credentials) < 1 || len(credentials) > 2 {
		return nil, dkim2model.ErrInvalid
	}
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].Algorithm() < credentials[j].Algorithm() })
	records := make([]dnsupdate.ExpectedTXT, len(credentials))
	for index, credential := range credentials {
		if credential.Algorithm() != dkim2model.AlgorithmRSASHA256 && credential.Algorithm() != dkim2model.AlgorithmEd25519SHA256 {
			return nil, dkim2model.ErrInvalid
		}
		records[index] = dnsupdate.ExpectedTXT{
			Owner:   credential.Selector() + "._domainkey." + domain + ".",
			Content: dnsRecord(credential),
		}
	}
	return records, nil
}

// sameExpectedRecords compares ordered public activation evidence without formatting it.
func sameExpectedRecords(left, right []dnsupdate.ExpectedTXT) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// generationEquivalentExceptState proves that commit changed only the candidate root state.
func generationEquivalentExceptState(left, right *dkim2model.Generation) bool {
	if left == nil || right == nil || left.Number() != right.Number() {
		return false
	}
	materials := right.KeyMaterials()
	defer closeMaterials(materials)
	normalized, err := dkim2model.NewGenerationWithState(
		right.Number(), left.State(), right.Handles(), right.Profiles(), right.Credentials(), right.Policies(), materials,
	)
	if err != nil {
		return false
	}
	defer func() { _ = normalized.Close() }()
	return left.Equivalent(normalized)
}

// reportRotation records the durable outcome before attempting bounded operator output.
func (m *DKIM2Manager) reportRotation(result *RunResult, outcome DKIM2Outcome) error {
	result.DKIM2Outcome = outcome
	message := "DKIM2 rotation outcome: " + string(outcome) + "\n"
	if _, err := fmt.Fprint(m.out, message); err != nil {
		result.ReportingFailed = true
		if outcome == DKIM2OutcomeStaged || outcome == DKIM2OutcomeActivated || outcome == DKIM2OutcomeAlreadyActivated ||
			outcome == DKIM2OutcomeRetired || outcome == DKIM2OutcomeAlreadyRetired {
			return nil
		}
		return errors.New("DKIM2 rotation outcome reporting failed")
	}
	return nil
}

// reportRotationDryRun truthfully distinguishes ephemeral planning from protected resume.
func (m *DKIM2Manager) reportRotationDryRun(result *RunResult, resuming bool) error {
	result.DKIM2Outcome = DKIM2OutcomeDryRun
	message := "DKIM2 rotation outcome: dry-run; apply creates new random keys\n"
	if resuming {
		message = "DKIM2 rotation outcome: dry-run; apply reuses stored candidate\n"
	}
	if _, err := fmt.Fprint(m.out, message); err != nil {
		result.ReportingFailed = true
		return errors.New("DKIM2 rotation outcome reporting failed")
	}
	return nil
}
