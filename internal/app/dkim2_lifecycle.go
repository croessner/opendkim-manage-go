package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

// autoRotate creates or resumes one complete all-due autonomous v3 successor.
func (m *DKIM2Manager) autoRotate(ctx context.Context, result *RunResult) error {
	return m.runAutomaticCampaign(ctx, result)
}

// observeLifecycle derives one bounded state from authoritative LDAP and DNS reads only.
func (m *DKIM2Manager) observeLifecycle(ctx context.Context, result *RunResult) error {
	if m.rotationRepository == nil || m.newPresenceObserver == nil || result == nil {
		return errors.New("DKIM2 lifecycle observation dependencies are unavailable")
	}
	domain, err := exactCanonical(m.opts.Domains[0], dkim2model.CanonicalDomain)
	if err != nil {
		return errors.New("DKIM2 lifecycle observation domain is invalid")
	}
	binding := configuredLifecycleBinding(m.cfg.DKIM2.TenantID, domain, m.cfg.DKIM2.ProfileUse)
	current, err := m.rotationRepository.LoadCurrent(ctx)
	if err != nil || current == nil {
		return errors.New("DKIM2 lifecycle observation cannot load current state safely")
	}
	defer func() { _ = current.Close() }()
	history, err := m.rotationRepository.LoadRetainedHistory(ctx, m.cfg.DKIM2.HistoryLimit)
	if err != nil || !history.Complete {
		return errors.New("DKIM2 lifecycle observation requires complete retained history")
	}
	pendingNumber, err := exactPendingSuccessor(history, current.Number())
	if err != nil {
		return errors.New("DKIM2 lifecycle observation found ambiguous retained state")
	}
	observer, err := m.newPresenceObserver(m.cfg)
	if err != nil || observer == nil {
		return errors.New("DKIM2 lifecycle DNS observer is unavailable")
	}
	if pendingNumber != 0 {
		prepared, loadErr := m.rotationRepository.LoadPending(ctx, pendingNumber, m.cfg.DKIM2.HistoryLimit)
		if loadErr != nil {
			return errors.New("DKIM2 lifecycle candidate observation is unavailable")
		}
		defer func() { _ = prepared.Close() }()
		candidate, candidateErr := prepared.Generation()
		if candidateErr != nil {
			return errors.New("DKIM2 lifecycle candidate observation is malformed")
		}
		defer func() { _ = candidate.Close() }()
		intentBinding, intentErr := preparedRotationBinding(current, prepared, history)
		if intentErr != nil || intentBinding != binding {
			return errors.New("DKIM2 lifecycle candidate does not match the observed binding")
		}
		records, recordErr := rotationExpectedRecords(candidate, binding.tenant, binding.domain, binding.use)
		if recordErr != nil {
			return errors.New("DKIM2 lifecycle candidate does not match the observed binding")
		}
		phase, phaseErr := observeCandidateRecordSet(ctx, observer, records)
		if phaseErr != nil {
			return phaseErr
		}
		if phase == dkim2model.LifecyclePhaseStaged && candidate.State() == dkim2model.DatasetStateCommitted {
			phase = dkim2model.LifecyclePhaseCommittedUnreachable
		}
		return m.emitLifecycleObservation(result, candidate, binding, phase)
	}

	predecessorNumber, predecessorFound := immediateCommittedPredecessor(history, current.Number())
	if !predecessorFound {
		return m.emitLifecycleObservation(result, current, binding, dkim2model.LifecyclePhaseIdle)
	}
	predecessor, err := m.rotationRepository.LoadRetainedGeneration(ctx, predecessorNumber, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return errors.New("DKIM2 lifecycle predecessor observation is unavailable")
	}
	defer func() { _ = predecessor.Close() }()
	transition, err := dkim2model.PlanRetirement(current, predecessor)
	if err != nil {
		return errors.New("DKIM2 lifecycle predecessor diff is ambiguous")
	}
	defer func() { _ = transition.Close() }()
	if modelLifecycleBinding(transition.Binding()) != binding {
		return m.emitLifecycleObservation(result, current, binding, dkim2model.LifecyclePhaseIdle)
	}
	activeRecords, err := lifecycleExpectedRecords(transition.ActiveCredentials(), domain)
	if err != nil {
		return errors.New("DKIM2 lifecycle active DNS expectation is malformed")
	}
	activePhase, err := observeCandidateRecordSet(ctx, observer, activeRecords)
	if err != nil {
		return err
	}
	if activePhase == dkim2model.LifecyclePhaseDNSConflict || activePhase == dkim2model.LifecyclePhaseDNSPending {
		return m.emitLifecycleObservation(result, current, binding, activePhase)
	}
	retiringRecords, err := lifecycleExpectedRecords(transition.RetiringCredentials(), domain)
	if err != nil {
		return errors.New("DKIM2 lifecycle predecessor DNS expectation is malformed")
	}
	oldObservations, err := observeDualRecordSet(ctx, observer, retiringRecords)
	if err != nil {
		return err
	}
	activation, now, err := m.validateRetirementClock(ctx, current.Number())
	if err != nil {
		return errors.New("DKIM2 lifecycle activation clock is untrusted")
	}
	overlapProven := now.Sub(activation.ModifiedAt) >= 0 &&
		now.Sub(activation.ModifiedAt) >= time.Duration(m.cfg.DKIM2.RetirementMinOverlapSeconds)*time.Second
	oldPhase := classifyPredecessorObservation(oldObservations, overlapProven)
	if oldPhase == 0 {
		return errors.New("DKIM2 lifecycle predecessor DNS state is partial or uncertain")
	}
	return m.emitLifecycleObservation(result, current, binding, oldPhase)
}

// observeDualRecordSet reads each exact record through both configured channels.
func observeDualRecordSet(ctx context.Context, observer dkim2PresenceObserver, records []dnsupdate.ExpectedTXT) ([]dnsupdate.PresenceObservation, error) {
	if observer == nil || len(records) < 1 || len(records) > 2 {
		return nil, errors.New("DKIM2 lifecycle DNS observation request is invalid")
	}
	observations := make([]dnsupdate.PresenceObservation, len(records))
	for index, record := range records {
		observation, err := observer.ObserveChannels(ctx, record)
		if err != nil {
			return nil, errors.New("DKIM2 lifecycle DNS observation is uncertain")
		}
		observations[index] = observation
	}
	return observations, nil
}

// observeCandidateRecordSet distinguishes exact dual-channel proof, propagation, and conflict.
func observeCandidateRecordSet(ctx context.Context, observer dkim2PresenceObserver, records []dnsupdate.ExpectedTXT) (dkim2model.LifecyclePhase, error) {
	observations, err := observeDualRecordSet(ctx, observer, records)
	if err != nil {
		return 0, err
	}
	pending := false
	for _, observation := range observations {
		if observation.Authoritative == dnsupdate.PresenceUncertain || observation.Recursive == dnsupdate.PresenceUncertain {
			return 0, errors.New("DKIM2 lifecycle candidate DNS state is uncertain")
		}
		if observation.Authoritative == dnsupdate.PresenceConflict || observation.Recursive == dnsupdate.PresenceConflict {
			return dkim2model.LifecyclePhaseDNSConflict, nil
		}
		if observation.Authoritative != dnsupdate.PresenceExact || observation.Recursive != dnsupdate.PresenceExact {
			pending = true
		}
	}
	if pending {
		return dkim2model.LifecyclePhaseDNSPending, nil
	}
	return dkim2model.LifecyclePhaseStaged, nil
}

// classifyPredecessorObservation enforces cardinality-neutral all-record retirement states.
func classifyPredecessorObservation(observations []dnsupdate.PresenceObservation, overlapProven bool) dkim2model.LifecyclePhase {
	if len(observations) < 1 || len(observations) > 2 {
		return 0
	}
	present, cached, absent := 0, 0, 0
	for _, observation := range observations {
		switch {
		case observation.Authoritative == dnsupdate.PresenceConflict || observation.Recursive == dnsupdate.PresenceConflict:
			return dkim2model.LifecyclePhaseDNSConflict
		case observation.Authoritative == dnsupdate.PresenceExact && observation.Recursive == dnsupdate.PresenceExact:
			present++
		case observation.Authoritative == dnsupdate.PresenceAbsent && observation.Recursive == dnsupdate.PresenceExact:
			cached++
		case observation.Authoritative == dnsupdate.PresenceAbsent && observation.Recursive == dnsupdate.PresenceAbsent:
			absent++
		default:
			return 0
		}
	}
	if absent == len(observations) {
		return dkim2model.LifecyclePhaseRetired
	}
	if present == len(observations) {
		if overlapProven {
			return dkim2model.LifecyclePhaseRetireEligible
		}
		return dkim2model.LifecyclePhaseObserving
	}
	if present+cached+absent == len(observations) {
		return dkim2model.LifecyclePhaseObserving
	}
	return dkim2model.LifecyclePhaseDNSConflict
}

// emitLifecycleObservation builds and writes the approved bounded status projection.
func (m *DKIM2Manager) emitLifecycleObservation(result *RunResult, generation *dkim2model.Generation, binding lifecycleBinding, phase dkim2model.LifecyclePhase) error {
	policy, found := exactPolicy(generation, binding.tenant, binding.domain, binding.use)
	if !found {
		return errors.New("DKIM2 lifecycle observed binding is unavailable")
	}
	credentials := credentialsForProfile(generation, policy.ProfileID())
	if len(credentials) < 1 || len(credentials) > 2 {
		return errors.New("DKIM2 lifecycle observed credentials are ambiguous")
	}
	statusCredentials := make([]dkim2model.ObservationCredential, len(credentials))
	for index, credential := range credentials {
		statusCredentials[index], _ = dkim2model.NewObservationCredential(credential.Selector(), credential.Algorithm())
	}
	observation, err := dkim2model.NewLifecycleObservation(generation.Number(), phase, binding.domain, statusCredentials)
	if err != nil {
		return errors.New("DKIM2 lifecycle observation is malformed")
	}
	result.DKIM2Outcome = DKIM2Outcome(phase.Name())
	return m.reportLifecycleObservation(observation)
}

// forwardRollback rebases one exact retained committed binding into a strictly newer generation.
func (m *DKIM2Manager) forwardRollback(ctx context.Context, result *RunResult) error {
	if m.rotationRepository == nil || result == nil {
		return errors.New("DKIM2 forward rollback repository is unavailable")
	}
	domain, err := exactCanonical(m.opts.Domains[0], dkim2model.CanonicalDomain)
	if err != nil {
		return errors.New("DKIM2 forward rollback domain is invalid")
	}
	if m.opts.ResumeGenerationSet {
		return m.resumeForwardRollback(ctx, result, domain)
	}
	current, err := m.rotationRepository.LoadCurrent(ctx)
	if err != nil || current == nil {
		return errors.New("DKIM2 forward rollback cannot load current state safely")
	}
	defer func() { _ = current.Close() }()
	if _, err := m.loadMutationHistory(ctx, current); err != nil {
		return errors.New("DKIM2 forward rollback requires complete unambiguous history")
	}
	if current.Number() == ^uint64(0) {
		return errors.New("DKIM2 generation counter is exhausted")
	}
	source, err := m.rotationRepository.LoadRetainedGeneration(ctx, m.opts.RollbackFromGeneration, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return errors.New("DKIM2 forward rollback source cannot be loaded safely")
	}
	defer func() { _ = source.Close() }()
	transition, err := dkim2model.PlanForwardRollback(dkim2model.ForwardRollbackPlan{
		Current: current, Source: source, NextGeneration: current.Number() + 1,
		TenantID: m.cfg.DKIM2.TenantID, Domain: domain, Use: dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse),
	})
	if err != nil {
		return errors.New("DKIM2 forward rollback source intent is invalid")
	}
	defer func() { _ = transition.Close() }()
	candidate, err := transition.Generation()
	if err != nil {
		return errors.New("DKIM2 forward rollback candidate is unavailable")
	}
	defer func() { _ = candidate.Close() }()
	if m.opts.DryRun {
		return m.reportForwardRollbackDryRun(result, false)
	}
	prepared, err := m.stageExactCandidate(ctx, candidate)
	if err != nil {
		return err
	}
	return m.continuePreparedRotation(ctx, result, prepared, configuredLifecycleBinding(m.cfg.DKIM2.TenantID, domain, m.cfg.DKIM2.ProfileUse), false, m.opts.PrepareOnly)
}

// resumeForwardRollback proves the stored candidate is the exact rebase of the named retained source.
func (m *DKIM2Manager) resumeForwardRollback(ctx context.Context, result *RunResult, domain string) error {
	prepared, err := m.rotationRepository.LoadPending(ctx, m.opts.ResumeGeneration, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return errors.New("DKIM2 stored forward rollback candidate cannot be resumed safely")
	}
	stored, err := prepared.Generation()
	if err != nil {
		_ = prepared.Close()
		return errors.New("DKIM2 stored forward rollback candidate is malformed")
	}
	defer func() { _ = stored.Close() }()
	predecessor, err := m.rotationRepository.LoadRetainedGeneration(ctx, prepared.ExpectedCurrent(), m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		_ = prepared.Close()
		return errors.New("DKIM2 forward rollback predecessor cannot be loaded safely")
	}
	defer func() { _ = predecessor.Close() }()
	source, err := m.rotationRepository.LoadRetainedGeneration(ctx, m.opts.RollbackFromGeneration, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		_ = prepared.Close()
		return errors.New("DKIM2 forward rollback source cannot be loaded safely")
	}
	defer func() { _ = source.Close() }()
	transition, err := dkim2model.PlanForwardRollback(dkim2model.ForwardRollbackPlan{
		Current: predecessor, Source: source, NextGeneration: prepared.CandidateNumber(),
		TenantID: m.cfg.DKIM2.TenantID, Domain: domain, Use: dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse),
	})
	if err != nil {
		_ = prepared.Close()
		return errors.New("DKIM2 stored forward rollback source intent is invalid")
	}
	defer func() { _ = transition.Close() }()
	expected, err := transition.Generation()
	if err != nil || !generationEquivalentExceptState(expected, stored) {
		if expected != nil {
			_ = expected.Close()
		}
		_ = prepared.Close()
		return errors.New("DKIM2 stored forward rollback candidate does not match its source intent")
	}
	_ = expected.Close()
	if m.opts.DryRun {
		_ = prepared.Close()
		return m.reportForwardRollbackDryRun(result, true)
	}
	return m.continuePreparedRotation(ctx, result, prepared, configuredLifecycleBinding(m.cfg.DKIM2.TenantID, domain, m.cfg.DKIM2.ProfileUse), m.opts.DryRun, m.opts.PrepareOnly)
}

// reportForwardRollbackDryRun distinguishes protected retained-source reuse from key rotation.
func (m *DKIM2Manager) reportForwardRollbackDryRun(result *RunResult, resuming bool) error {
	result.DKIM2Outcome = DKIM2OutcomeDryRun
	message := "DKIM2 forward rollback outcome: dry-run; apply rebases retained protected source\n"
	if resuming {
		message = "DKIM2 forward rollback outcome: dry-run; apply reuses stored source-bound candidate\n"
	}
	if _, err := fmt.Fprint(m.out, message); err != nil {
		result.ReportingFailed = true
		return errors.New("DKIM2 forward rollback outcome reporting failed")
	}
	return nil
}

// retire removes only the exact old TXT values after fresh proof and overlap evidence.
func (m *DKIM2Manager) retire(ctx context.Context, result *RunResult) error {
	if m.rotationRepository == nil || result == nil || m.newRotationProof == nil || m.newRotationRetirer == nil {
		return errors.New("DKIM2 retirement dependencies are unavailable")
	}
	domain, err := exactCanonical(m.opts.Domains[0], dkim2model.CanonicalDomain)
	if err != nil {
		return errors.New("DKIM2 retirement domain is invalid")
	}
	current, err := m.rotationRepository.LoadCurrent(ctx)
	if err != nil || current == nil {
		return errors.New("DKIM2 retirement cannot load current state safely")
	}
	defer func() { _ = current.Close() }()
	if err := m.requireRetirementFence(ctx, current.Number()); err != nil {
		return err
	}
	predecessor, err := m.rotationRepository.LoadRetainedGeneration(ctx, m.opts.RetireGeneration, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return errors.New("DKIM2 retirement predecessor cannot be loaded safely")
	}
	defer func() { _ = predecessor.Close() }()
	transition, err := dkim2model.PlanRetirement(current, predecessor)
	if err != nil || transition.Binding().Domain() != domain ||
		transition.Binding().TenantID() != m.cfg.DKIM2.TenantID ||
		transition.Binding().Use() != dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse) {
		if transition != nil {
			_ = transition.Close()
		}
		return errors.New("DKIM2 retirement predecessor diff is not one exact rotated binding")
	}
	defer func() { _ = transition.Close() }()
	activation, now, err := m.validateRetirementClock(ctx, transition.CurrentGeneration())
	if err != nil {
		return err
	}
	if err := dkim2model.ValidateRetirementEvidence(transition.CurrentGeneration(), dkim2model.RetirementEvidence{
		CurrentGeneration: activation.Generation, ActivatedAt: activation.ModifiedAt, ObservedAt: now,
		MinimumOverlap: time.Duration(m.cfg.DKIM2.RetirementMinOverlapSeconds) * time.Second,
		Attestations: dkim2model.RetirementAttestations{
			RuntimeReload: m.opts.AttestRuntimeReload, RepeatedReadiness: m.opts.AttestReadiness,
			Queues: m.opts.AttestQueues, EmittedSignatures: m.opts.AttestEmittedSignatures,
			ExternalVerify: m.opts.AttestExternalVerification, Backup: m.opts.AttestBackup,
			RollbackAuthority: m.opts.AttestRollbackAuthority,
		},
	}); err != nil {
		return errors.New("DKIM2 retirement overlap or attestations are insufficient")
	}
	activeRecords, err := lifecycleExpectedRecords(transition.ActiveCredentials(), domain)
	if err != nil {
		return errors.New("DKIM2 retirement replacement DNS expectation is malformed")
	}
	retiringRecords, err := lifecycleExpectedRecords(transition.RetiringCredentials(), domain)
	if err != nil {
		return errors.New("DKIM2 retirement old DNS expectation is malformed")
	}
	proof, err := m.newRotationProof(m.cfg)
	if err != nil || proof == nil || proof.ProveAll(ctx, activeRecords) != nil {
		return errors.New("DKIM2 retirement requires fresh replacement-key DNS proof")
	}
	retirer, err := m.newRotationRetirer(m.cfg)
	if err != nil || retirer == nil {
		return errors.New("DKIM2 retirement DNS client is unavailable")
	}
	states := make([]dnsupdate.PresenceState, len(retiringRecords))
	for index, record := range retiringRecords {
		states[index], err = retirer.Observe(ctx, record)
		if err != nil || states[index] == dnsupdate.PresenceConflict || states[index] == dnsupdate.PresenceUncertain {
			return errors.New("DKIM2 retirement old DNS state is conflicting or uncertain")
		}
		if states[index] == dnsupdate.PresenceAbsent && !m.opts.ResumeRetirement {
			return errors.New("DKIM2 partial retirement requires explicit --resume-retirement")
		}
	}
	if m.opts.DryRun {
		return m.reportRotation(result, DKIM2OutcomeDryRun)
	}
	result.DKIM2Outcome = DKIM2OutcomeRetirementPending
	removed := 0
	zone := domain + "."
	for index, record := range retiringRecords {
		if states[index] == dnsupdate.PresenceAbsent {
			continue
		}
		if err := m.recheckRetirementFence(ctx, activation); err != nil {
			return err
		}
		deleteResult, deleteErr := retirer.DeleteExact(ctx, zone, record)
		if deleteErr != nil || deleteResult == dnsupdate.DeleteResumable {
			return errors.New("DKIM2 retirement deletion requires explicit resume")
		}
		if deleteResult != dnsupdate.DeleteRemoved && deleteResult != dnsupdate.DeleteAlreadyAbsent {
			return errors.New("DKIM2 retirement deletion outcome is uncertain")
		}
		removed++
	}
	if removed == 0 {
		return m.reportRotation(result, DKIM2OutcomeAlreadyRetired)
	}
	return m.reportRotation(result, DKIM2OutcomeRetired)
}

// stageExactCandidate reconciles a lost staging response only against exact immutable readback.
func (m *DKIM2Manager) stageExactCandidate(ctx context.Context, candidate *dkim2model.Generation) (*dkim2store.PreparedGeneration, error) {
	prepared, err := m.rotationRepository.Stage(ctx, candidate, m.cfg.DKIM2.HistoryLimit)
	if err == nil && preparedMatchesCandidate(prepared, candidate) {
		return prepared, nil
	}
	if prepared != nil {
		_ = prepared.Close()
	}
	prepared, readErr := m.rotationRepository.LoadPending(ctx, candidate.Number(), m.cfg.DKIM2.HistoryLimit)
	if readErr != nil || !preparedMatchesCandidate(prepared, candidate) {
		if prepared != nil {
			_ = prepared.Close()
		}
		return nil, errors.New("DKIM2 staging outcome is uncertain")
	}
	return prepared, nil
}

// validateRetirementClock reads the pointer generation and operational activation clock atomically.
func (m *DKIM2Manager) validateRetirementClock(ctx context.Context, expected uint64) (dkim2store.CurrentActivation, time.Time, error) {
	activation, err := m.rotationRepository.LoadCurrentActivation(ctx)
	if err != nil || activation.Generation != expected || activation.ModifiedAt.Location() != time.UTC || activation.ModifiedAt.IsZero() {
		return dkim2store.CurrentActivation{}, time.Time{}, errors.New("DKIM2 retirement activation evidence is invalid")
	}
	now, err := m.utcNow()
	if err != nil || activation.ModifiedAt.After(now.Add(time.Duration(m.cfg.DKIM2.MaxClockSkewSeconds)*time.Second)) {
		return dkim2store.CurrentActivation{}, time.Time{}, errors.New("DKIM2 retirement activation clock is untrusted")
	}
	return activation, now, nil
}

// recheckRetirementCurrent closes the race between validation and each value-aware DNS delete.
func (m *DKIM2Manager) recheckRetirementCurrent(ctx context.Context, expected dkim2store.CurrentActivation) error {
	observed, err := m.rotationRepository.LoadCurrentActivation(ctx)
	if err != nil || observed.Generation != expected.Generation || !observed.ModifiedAt.Equal(expected.ModifiedAt) {
		return errors.New("DKIM2 current pointer changed during retirement")
	}
	return nil
}

// requireRetirementFence rejects DNS retirement while any higher successor is retained.
func (m *DKIM2Manager) requireRetirementFence(ctx context.Context, current uint64) error {
	history, err := m.rotationRepository.LoadRetainedHistory(ctx, m.cfg.DKIM2.HistoryLimit)
	if err != nil || !history.Complete {
		return errors.New("DKIM2 retirement lifecycle fence is unavailable")
	}
	pending, err := exactPendingSuccessor(history, current)
	if err != nil || pending != 0 {
		return errors.New("DKIM2 retirement is blocked by retained successor state")
	}
	return nil
}

// recheckRetirementFence binds every DNS delete to unchanged current and successor absence.
func (m *DKIM2Manager) recheckRetirementFence(ctx context.Context, expected dkim2store.CurrentActivation) error {
	if err := m.requireRetirementFence(ctx, expected.Generation); err != nil {
		return err
	}
	return m.recheckRetirementCurrent(ctx, expected)
}

// utcNow returns one injected canonical UTC lifecycle clock.
func (m *DKIM2Manager) utcNow() (time.Time, error) {
	if m.now == nil {
		return time.Time{}, errors.New("DKIM2 lifecycle clock is unavailable")
	}
	now := m.now()
	if now.IsZero() || now.Location() != time.UTC {
		return time.Time{}, errors.New("DKIM2 lifecycle clock is not canonical UTC")
	}
	return now, nil
}

// exactPendingSuccessor permits at most one immediate staging or committed-unreachable root.
func exactPendingSuccessor(history dkim2store.RetainedHistory, current uint64) (uint64, error) {
	if !retainedRootsContiguous(history.Roots) {
		return 0, dkim2store.ErrMalformed
	}
	foundCurrent := false
	pending := uint64(0)
	for _, root := range history.Roots {
		switch {
		case root.Number == current && root.State == dkim2model.DatasetStateCommitted:
			foundCurrent = true
		case root.Number < current && root.State == dkim2model.DatasetStateCommitted:
		case current != ^uint64(0) && root.Number == current+1 &&
			(root.State == dkim2model.DatasetStateStaging || root.State == dkim2model.DatasetStateCommitted) && pending == 0:
			pending = root.Number
		default:
			return 0, dkim2store.ErrMalformed
		}
	}
	if !foundCurrent {
		return 0, dkim2store.ErrMalformed
	}
	return pending, nil
}

// immediateCommittedPredecessor locates only the exact prior committed root.
func immediateCommittedPredecessor(history dkim2store.RetainedHistory, current uint64) (uint64, bool) {
	if current <= 1 {
		return 0, false
	}
	for _, root := range history.Roots {
		if root.Number == current-1 && root.State == dkim2model.DatasetStateCommitted {
			return root.Number, true
		}
	}
	return 0, false
}

// preparedRotationBinding proves fresh normal-rotation intent before automatic or explicit continuation.
func preparedRotationBinding(current *dkim2model.Generation, prepared *dkim2store.PreparedGeneration, history dkim2store.RetainedHistory) (lifecycleBinding, error) {
	if current == nil || prepared == nil || prepared.ExpectedCurrent() != current.Number() {
		return lifecycleBinding{}, dkim2model.ErrInvalid
	}
	candidate, err := prepared.Generation()
	if err != nil {
		return lifecycleBinding{}, err
	}
	defer func() { _ = candidate.Close() }()
	lineage, err := history.LineageHistory()
	if err != nil {
		return lifecycleBinding{}, err
	}
	binding, err := dkim2model.ValidateRotationCandidateIntent(current, candidate, lineage)
	if err != nil {
		return lifecycleBinding{}, err
	}
	result := modelLifecycleBinding(binding)
	if !result.valid() {
		return lifecycleBinding{}, dkim2model.ErrInvalid
	}
	return result, nil
}

// cloneGenerationWithState changes only detached root-state evidence for comparison and tests.
func cloneGenerationWithState(source *dkim2model.Generation, state dkim2model.DatasetState) (*dkim2model.Generation, error) {
	if source == nil {
		return nil, dkim2model.ErrInvalid
	}
	materials := source.KeyMaterials()
	defer closeMaterials(materials)
	return dkim2model.NewGenerationWithState(
		source.Number(), state, source.Handles(), source.Profiles(), source.Credentials(), source.Policies(), materials,
	)
}

// lifecycleExpectedRecords derives exact public DNS expectations without exposing protected handles.
func lifecycleExpectedRecords(credentials []dkim2model.LifecycleCredential, domain string) ([]dnsupdate.ExpectedTXT, error) {
	if len(credentials) < 1 || len(credentials) > 2 {
		return nil, dkim2model.ErrInvalid
	}
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].Algorithm() < credentials[j].Algorithm() })
	result := make([]dnsupdate.ExpectedTXT, len(credentials))
	for index, credential := range credentials {
		keyType := "rsa"
		if credential.Algorithm() == dkim2model.AlgorithmEd25519SHA256 {
			keyType = "ed25519"
		} else if credential.Algorithm() != dkim2model.AlgorithmRSASHA256 {
			return nil, dkim2model.ErrInvalid
		}
		public := credential.DNSPublicKeyBytes()
		if len(public) == 0 {
			return nil, dkim2model.ErrInvalid
		}
		result[index] = dnsupdate.ExpectedTXT{
			Owner:   credential.Selector() + "._domainkey." + domain + ".",
			Content: "v=DKIM1; k=" + keyType + "; h=sha256; p=" + base64.StdEncoding.EncodeToString(public),
		}
		clear(public)
	}
	return result, nil
}

// reportLifecycleObservation emits only the approved bounded status vocabulary.
func (m *DKIM2Manager) reportLifecycleObservation(observation dkim2model.LifecycleObservation) error {
	if !observation.Phase().Known() || observation.Generation() == 0 || len(observation.Credentials()) > 2 {
		return errors.New("DKIM2 lifecycle observation is invalid")
	}
	credentials := observation.Credentials()
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].Algorithm() < credentials[j].Algorithm() })
	if _, err := fmt.Fprintf(m.out, "DKIM2 lifecycle generation=%d phase=%s domain=%s credentials=%d",
		observation.Generation(), observation.Phase().Name(), observation.Domain(), len(credentials)); err != nil {
		return errors.New("DKIM2 lifecycle observation reporting failed")
	}
	for _, credential := range credentials {
		if _, err := fmt.Fprintf(m.out, " selector=%s algorithm=%s", credential.Selector(), credential.Algorithm()); err != nil {
			return errors.New("DKIM2 lifecycle observation reporting failed")
		}
	}
	_, err := fmt.Fprintln(m.out)
	if err != nil {
		return errors.New("DKIM2 lifecycle observation reporting failed")
	}
	return nil
}
