package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

// resumeCreate recovers only one explicit, fully validated native additive candidate without restaging.
func (m *DKIM2Manager) resumeCreate(ctx context.Context) error {
	if !m.cfg.DKIM2.RotationEnabled || m.campaignRepository == nil || m.opts.ResumeGeneration < 2 {
		return errors.New("native DKIM2 create recovery requires an explicit v3 successor and native authorities")
	}
	domains, err := canonicalUnique(m.opts.Domains, dkim2model.CanonicalDomain)
	if err != nil {
		return errors.New("native DKIM2 create recovery domain scope is invalid")
	}
	algorithms, err := m.algorithms()
	if err != nil {
		return err
	}
	intent := dkim2model.CreateCandidateIntent{TenantID: m.cfg.DKIM2.TenantID, Domains: domains,
		Use: dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse), Algorithms: algorithms, RSABits: m.opts.Size,
		Selectors: m.opts.Selectors, FeedbackRouteID: m.cfg.DKIM2.FeedbackRouteID, MaximumBindings: m.cfg.DKIM2.MaxCampaignBindings}
	prepared, err := m.campaignRepository.LoadPending(ctx, m.opts.ResumeGeneration, m.cfg.DKIM2.HistoryLimit)
	if err != nil || prepared == nil {
		if prepared != nil {
			_ = prepared.Close()
		}
		return errors.New("native DKIM2 create recovery candidate cannot be read completely")
	}
	defer func() { _ = prepared.Close() }()
	metadata, ok := prepared.CampaignMetadata()
	if !ok || metadata.SourceGeneration() != prepared.ExpectedCurrent() ||
		metadata.Generation() != m.opts.ResumeGeneration || prepared.CandidateNumber() != m.opts.ResumeGeneration {
		return errors.New("native DKIM2 create recovery commitment is missing or unrelated")
	}
	candidate, err := prepared.Generation()
	if err != nil || metadata.ValidateCandidate(candidate) != nil {
		if candidate != nil {
			_ = candidate.Close()
		}
		return errors.New("native DKIM2 create recovery commitment is invalid")
	}
	defer func() { _ = candidate.Close() }()
	source, err := m.campaignRepository.LoadRetainedGeneration(ctx, metadata.SourceGeneration(), m.cfg.DKIM2.HistoryLimit)
	if err != nil || source == nil {
		if source != nil {
			_ = source.Close()
		}
		return errors.New("native DKIM2 create recovery source cannot be read completely")
	}
	defer func() { _ = source.Close() }()
	history, err := m.campaignRepository.LoadRetainedHistory(ctx, m.cfg.DKIM2.HistoryLimit)
	if err != nil || !history.Complete || source.Number() != metadata.SourceGeneration() {
		return errors.New("native DKIM2 create recovery history is incomplete")
	}
	next, err := exactPendingSuccessor(history, source.Number())
	if err != nil || next != candidate.Number() {
		return errors.New("native DKIM2 create recovery found unrelated retained work")
	}
	lineage, err := history.LineageHistory()
	if err != nil {
		return errors.New("native DKIM2 create recovery lineage is incomplete")
	}
	bindings, err := dkim2model.ValidateCreateCandidateIntent(source, candidate, lineage, intent)
	if err != nil || len(bindings) != len(domains) {
		return errors.New("native DKIM2 stored candidate does not match the exact inactive create request")
	}
	if err := m.requireCreateResumeReadback(ctx, candidate, metadata, prepared.ObservedCurrent()); err != nil {
		return err
	}
	if m.opts.DryRun {
		_, err = fmt.Fprintf(m.out, "dry-run: validated stored inactive DKIM2 generation %d with %d new profile(s); no random, LDAP, or DNS writes\n", candidate.Number(), len(bindings))
		return err
	}
	// Load authentication only after authorization and complete recovery validation.
	if m.opts.UpdateDNS && m.dns == nil {
		m.dns, err = dnsupdate.New(m.cfg)
		if err != nil {
			return errors.New("DKIM2 DNS updater is unavailable")
		}
	}
	if prepared.ObservedCurrent() != candidate.Number() {
		if prepared.ObservedCurrent() != source.Number() {
			return errors.New("native DKIM2 create recovery source is no longer current")
		}
		// A lost commit/switch response is safe only after the same complete current readback.
		_ = m.campaignRepository.CommitCampaignAndSwitch(ctx, prepared)
		if err := m.requireCreateResumeReadback(ctx, candidate, metadata, candidate.Number()); err != nil {
			return errors.New("native DKIM2 create recovery activation outcome is uncertain")
		}
	}
	if m.opts.UpdateDNS {
		if m.dns == nil {
			return errors.New("DKIM2 DNS updater is unavailable")
		}
		for _, binding := range bindings {
			policy, found := exactPolicy(candidate, binding.TenantID(), binding.Domain(), binding.Use())
			if !found {
				return errors.New("native DKIM2 create recovery DNS scope is invalid")
			}
			for _, credential := range credentialsForProfile(candidate, policy.ProfileID()) {
				if err := m.requireCreateResumeReadback(ctx, candidate, metadata, candidate.Number()); err != nil {
					return err
				}
				if err := m.dns.AddDKIMKey(binding.Domain(), credential.Selector(), dnsRecord(credential), ""); err != nil {
					return errors.New("native DKIM2 create recovery DNS publication is incomplete")
				}
			}
		}
		if err := m.requireCreateResumeReadback(ctx, candidate, metadata, candidate.Number()); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(m.out, "resumed inactive DKIM2 generation %d with %d new profile(s)\n", candidate.Number(), len(bindings))
	return err
}

// requireCreateResumeReadback fences every mutation with exact operation/content and native current evidence.
func (m *DKIM2Manager) requireCreateResumeReadback(ctx context.Context, candidate *dkim2model.Generation, metadata dkim2model.CandidateMetadata, current uint64) error {
	if err := ctx.Err(); err != nil {
		return errors.New("native DKIM2 create recovery deadline expired")
	}
	observed, err := m.campaignRepository.LoadPending(ctx, candidate.Number(), m.cfg.DKIM2.HistoryLimit)
	if observed != nil {
		defer func() { _ = observed.Close() }()
	}
	if err != nil || observed == nil || observed.ObservedCurrent() != current || !campaignPreparedMatches(observed, candidate, metadata) {
		return errors.New("native DKIM2 create recovery changed during readback")
	}
	actual, ok := observed.CampaignMetadata()
	if !ok || !metadata.ExactEqual(actual) ||
		current != metadata.SourceGeneration() && current != candidate.Number() {
		return errors.New("native DKIM2 create recovery operation changed during readback")
	}
	if current == candidate.Number() {
		generation, err := observed.Generation()
		if generation != nil {
			defer func() { _ = generation.Close() }()
		}
		if err != nil || generation == nil || generation.State() != dkim2model.DatasetStateCommitted {
			return errors.New("native DKIM2 create recovery current generation is not committed")
		}
	}
	return nil
}
