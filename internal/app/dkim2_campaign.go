package app

import (
	"context"
	"errors"
	"sort"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

type campaignDNSRecord struct {
	zone   string
	record dnsupdate.ExpectedTXT
}

// runAutomaticCampaign freezes every due binding into one autonomous v3 successor.
func (m *DKIM2Manager) runAutomaticCampaign(ctx context.Context, result *RunResult) error {
	if m == nil || m.campaignRepository == nil || result == nil {
		return errors.New("DKIM2 automatic campaign repository is unavailable")
	}
	current, err := m.campaignRepository.LoadCurrent(ctx)
	if err != nil || current == nil {
		return errors.New("DKIM2 automatic campaign cannot load current state safely")
	}
	defer func() { _ = current.Close() }()
	history, err := m.campaignRepository.LoadRetainedHistory(ctx, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return err
	}
	if !history.Complete {
		return errors.New("DKIM2 automatic campaign requires complete retained history")
	}
	pending, err := exactPendingSuccessor(history, current.Number())
	if err != nil {
		return errors.New("DKIM2 automatic campaign found ambiguous retained state")
	}
	if pending != 0 {
		prepared, loadErr := m.campaignRepository.LoadPending(ctx, pending, m.cfg.DKIM2.HistoryLimit)
		if loadErr != nil {
			return errors.New("DKIM2 automatic campaign cannot resume the protected candidate")
		}
		if m.opts.DryRun {
			_ = prepared.Close()
			return m.reportRotationDryRun(result, true)
		}
		return m.continueAutomaticCampaign(ctx, result, current, prepared)
	}
	lineage, err := history.LineageHistory()
	if err != nil {
		return errors.New("DKIM2 automatic campaign lineage is incomplete")
	}
	now, err := m.utcNow()
	if err != nil {
		return err
	}
	candidate, decisions, err := dkim2model.PlanGlobalRotation(dkim2model.GlobalRotationPlan{
		Current: current, NextGeneration: current.Number() + 1, Now: now, History: lineage,
		Identifiers: history, Random: m.random, Limits: configuredDKIM2RotationLimits(m.cfg.DKIM2, m.opts.Size),
	})
	if err != nil {
		return errors.New("DKIM2 automatic campaign eligibility or candidate is invalid")
	}
	if candidate == nil {
		if len(decisions) != 0 {
			return errors.New("DKIM2 automatic campaign planner returned inconsistent state")
		}
		if !m.opts.DryRun {
			reconciled, reconcileErr := m.reconcileCurrentDNS(ctx, current)
			if reconcileErr != nil {
				return reconcileErr
			}
			if err := m.applyAutomaticRetention(ctx); err != nil {
				return err
			}
			if reconciled {
				return m.reportRotation(result, DKIM2OutcomeReconciled)
			}
		}
		return m.reportRotation(result, DKIM2OutcomeIdle)
	}
	defer func() { _ = candidate.Close() }()
	if m.opts.DryRun {
		return m.reportRotationDryRun(result, false)
	}
	operation, err := dkim2model.GenerateOperationID(m.random)
	if err != nil {
		return errors.New("DKIM2 automatic campaign operation identity is unavailable")
	}
	metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, current.Number(), candidate)
	if err != nil {
		return errors.New("DKIM2 automatic campaign commitment is invalid")
	}
	prepared, err := m.campaignRepository.StageCampaign(ctx, candidate, metadata)
	if err != nil {
		prepared, err = m.campaignRepository.LoadPending(ctx, candidate.Number(), m.cfg.DKIM2.HistoryLimit)
		if err != nil || !campaignPreparedMatches(prepared, candidate, metadata) {
			if prepared != nil {
				_ = prepared.Close()
			}
			return errors.New("DKIM2 automatic campaign staging outcome is uncertain")
		}
	}
	return m.continueAutomaticCampaign(ctx, result, current, prepared)
}

// reconcileCurrentDNS restores absent exact current-generation RRsets without changing LDAP state.
func (m *DKIM2Manager) reconcileCurrentDNS(ctx context.Context, current *dkim2model.Generation) (bool, error) {
	bindings, err := dkim2model.ActiveBindings(current, m.cfg.DKIM2.MaxCampaignBindings)
	if err != nil {
		return false, errors.New("DKIM2 current DNS reconciliation binding inventory is invalid")
	}
	records, err := campaignExpectedRecords(current, bindings)
	if err != nil {
		return false, errors.New("DKIM2 current DNS reconciliation expectations are invalid")
	}
	if m.newRotationPublisher == nil || m.newRotationProof == nil {
		return false, errors.New("DKIM2 current DNS reconciliation dependencies are unavailable")
	}
	publisher, err := m.newRotationPublisher(m.cfg)
	if err != nil || publisher == nil {
		return false, errors.New("DKIM2 current DNS reconciliation publisher is unavailable")
	}
	proof, err := m.newRotationProof(m.cfg)
	if err != nil || proof == nil {
		return false, errors.New("DKIM2 current DNS reconciliation proof is unavailable")
	}
	expected := make([]dnsupdate.ExpectedTXT, len(records))
	reconciled := false
	if err := resolveCampaignUpdateZones(ctx, publisher, records); err != nil {
		return false, errors.New("DKIM2 current DNS reconciliation update zones are uncertain")
	}
	for index, item := range records {
		expected[index] = item.record
		publication, publishErr := publisher.PublishIfAbsent(ctx, item.zone, item.record)
		if publishErr != nil {
			return false, errors.New("DKIM2 current DNS reconciliation is conflicting or uncertain")
		}
		switch publication {
		case dnsupdate.PublishCreated:
			reconciled = true
		case dnsupdate.PublishAlreadyPresent:
		default:
			return false, errors.New("DKIM2 current DNS reconciliation outcome is invalid")
		}
	}
	if err := proof.ProveAll(ctx, expected); err != nil {
		return false, errors.New("DKIM2 current DNS reconciliation proof is pending, conflicting, or uncertain")
	}
	return reconciled, nil
}

func campaignPreparedMatches(prepared *dkim2store.PreparedGeneration, candidate *dkim2model.Generation, metadata dkim2model.CandidateMetadata) bool {
	if prepared == nil || candidate == nil || prepared.ExpectedCurrent() != metadata.SourceGeneration() ||
		prepared.CandidateNumber() != metadata.Generation() {
		return false
	}
	observed, ok := prepared.CampaignMetadata()
	if !ok || !observed.DigestEqual(metadata) {
		return false
	}
	stored, err := prepared.Generation()
	if err != nil {
		return false
	}
	defer func() { _ = stored.Close() }()
	return candidate.Equivalent(stored)
}

// continueAutomaticCampaign publishes all candidate keys before moving current exactly once.
func (m *DKIM2Manager) continueAutomaticCampaign(
	ctx context.Context, result *RunResult, source *dkim2model.Generation, prepared *dkim2store.PreparedGeneration,
) error {
	if source == nil || prepared == nil {
		return errors.New("DKIM2 automatic campaign evidence is unavailable")
	}
	defer func() { _ = prepared.Close() }()
	metadata, ok := prepared.CampaignMetadata()
	if !ok || metadata.SourceGeneration() != source.Number() {
		return errors.New("DKIM2 automatic campaign metadata is unavailable")
	}
	candidate, err := prepared.Generation()
	if err != nil || metadata.ValidateCandidate(candidate) != nil {
		if candidate != nil {
			_ = candidate.Close()
		}
		return errors.New("DKIM2 automatic campaign candidate is malformed")
	}
	defer func() { _ = candidate.Close() }()
	bindings, err := dkim2model.ChangedActiveBindings(source, candidate, m.cfg.DKIM2.MaxCampaignBindings)
	if err != nil || len(bindings) == 0 {
		return errors.New("DKIM2 automatic campaign candidate diff is ambiguous")
	}
	records, err := campaignExpectedRecords(candidate, bindings)
	if err != nil {
		return errors.New("DKIM2 automatic campaign DNS expectations are invalid")
	}
	if prepared.ObservedCurrent() == prepared.CandidateNumber() {
		if candidate.State() != dkim2model.DatasetStateCommitted {
			return errors.New("DKIM2 activated campaign candidate is malformed")
		}
		if err := m.applyAutomaticRetention(ctx); err != nil {
			return err
		}
		return m.reportRotation(result, DKIM2OutcomeAlreadyActivated)
	}
	if m.newRotationPublisher == nil || m.newRotationProof == nil {
		return errors.New("DKIM2 automatic campaign DNS dependencies are unavailable")
	}
	publisher, err := m.newRotationPublisher(m.cfg)
	if err != nil || publisher == nil {
		return errors.New("DKIM2 automatic campaign DNS publisher is unavailable")
	}
	proof, err := m.newRotationProof(m.cfg)
	if err != nil || proof == nil {
		return errors.New("DKIM2 automatic campaign DNS proof is unavailable")
	}
	public := make([]dnsupdate.ExpectedTXT, len(records))
	if err := resolveCampaignUpdateZones(ctx, publisher, records); err != nil {
		return errors.New("DKIM2 automatic campaign DNS update zones are uncertain")
	}
	for index, item := range records {
		public[index] = item.record
		if _, err := publisher.PublishIfAbsent(ctx, item.zone, item.record); err != nil {
			return errors.New("DKIM2 automatic campaign DNS publication is conflicting or uncertain")
		}
	}
	if err := proof.ProveAll(ctx, public); err != nil {
		return errors.New("DKIM2 automatic campaign DNS proof is pending, conflicting, or uncertain")
	}
	refreshed, err := m.campaignRepository.LoadPending(ctx, prepared.CandidateNumber(), m.cfg.DKIM2.HistoryLimit)
	if err != nil || !campaignPreparedMatches(refreshed, candidate, metadata) || refreshed.ObservedCurrent() != source.Number() {
		if refreshed != nil {
			_ = refreshed.Close()
		}
		return errors.New("DKIM2 automatic campaign changed before activation")
	}
	defer func() { _ = refreshed.Close() }()
	if err := proof.ProveAll(ctx, public); err != nil {
		return errors.New("DKIM2 automatic campaign final DNS proof is pending or uncertain")
	}
	if err := m.campaignRepository.CommitCampaignAndSwitch(ctx, refreshed); err != nil {
		reconciled, readErr := m.campaignRepository.LoadPending(ctx, prepared.CandidateNumber(), m.cfg.DKIM2.HistoryLimit)
		if readErr != nil || reconciled.ObservedCurrent() != prepared.CandidateNumber() || !campaignPreparedMatches(reconciled, candidate, metadata) {
			if reconciled != nil {
				_ = reconciled.Close()
			}
			return errors.New("DKIM2 automatic campaign activation outcome is uncertain")
		}
		_ = reconciled.Close()
	}
	if err := m.applyAutomaticRetention(ctx); err != nil {
		return err
	}
	return m.reportRotation(result, DKIM2OutcomeActivated)
}

// resolveCampaignUpdateZones resolves every unique logical binding domain
// before the first publication and replaces it only with proven SOA authority.
func resolveCampaignUpdateZones(
	ctx context.Context, publisher dkim2RotationPublisher, records []campaignDNSRecord,
) error {
	if ctx == nil || publisher == nil || len(records) == 0 {
		return dkim2model.ErrInvalid
	}
	resolved := make(map[string]string, len(records))
	for _, item := range records {
		if _, found := resolved[item.zone]; found {
			continue
		}
		authority, err := publisher.ResolveUpdateZone(ctx, item.zone)
		if err != nil {
			return err
		}
		resolved[item.zone] = authority
	}
	for index := range records {
		logical := records[index].zone
		authority := resolved[logical]
		if err := dnsupdate.ValidateResolvedUpdateZone(logical, authority, records[index].record); err != nil {
			return err
		}
		records[index].zone = authority
	}
	return nil
}

func campaignExpectedRecords(candidate *dkim2model.Generation, bindings []dkim2model.BindingIdentity) ([]campaignDNSRecord, error) {
	result := make([]campaignDNSRecord, 0, len(bindings)*2)
	owners := make(map[string]struct{}, len(bindings)*2)
	for _, binding := range bindings {
		records, err := rotationExpectedRecords(candidate, binding.TenantID(), binding.Domain(), binding.Use())
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if _, duplicate := owners[record.Owner]; duplicate {
				return nil, dkim2model.ErrInvalid
			}
			owners[record.Owner] = struct{}{}
			result = append(result, campaignDNSRecord{zone: binding.Domain() + ".", record: record})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].record.Owner < result[j].record.Owner })
	return result, nil
}

// applyAutomaticRetention deletes only a contiguous oldest v3 prefix above the configured rollback floor.
func (m *DKIM2Manager) applyAutomaticRetention(ctx context.Context) error {
	policy := m.cfg.DKIM2.Retention
	if !policy.Enabled {
		return nil
	}
	if plan, document, present, err := loadRetentionJournal(policy.JournalFile, policy.MaxJournalBytes); err != nil {
		return err
	} else if present {
		defer clear(document)
		if err := m.campaignRepository.DeleteGeneration(ctx, plan); err != nil {
			return errors.New("DKIM2 retention recovery is uncertain")
		}
		if err := removeRetentionJournal(policy.JournalFile, policy.MaxJournalBytes, document); err != nil {
			return err
		}
	}
	for deleted := 0; deleted < policy.MaxDeleteBatch; deleted++ {
		inventory, err := m.campaignRepository.InventoryGenerations(ctx)
		if err != nil {
			return errors.New("DKIM2 retention inventory is unavailable")
		}
		if len(inventory.Roots) <= policy.MaxGenerations {
			return nil
		}
		rollbackFloor := inventory.Current - uint64(policy.MinRollbackGenerations)
		if inventory.Current <= uint64(policy.MinRollbackGenerations) {
			return errors.New("DKIM2 retention is blocked by non-purgeable oldest generation")
		}
		target := uint64(0)
		for _, root := range inventory.Roots {
			if root.Number < rollbackFloor && root.Complete && root.Schema == dkim2model.SchemaVersionV3 &&
				root.State == dkim2model.DatasetStateCommitted && root.WasActive {
				target = root.Number
				break
			}
		}
		if target == 0 {
			return errors.New("DKIM2 retention is blocked by non-purgeable retained history")
		}
		plan, err := dkim2store.NewGenerationPurgePlan(inventory, target)
		if err != nil {
			return errors.New("DKIM2 retention plan is unavailable")
		}
		document, err := createRetentionJournal(policy.JournalFile, policy.MaxJournalBytes, plan)
		if err != nil {
			return err
		}
		if err := m.campaignRepository.DeleteGeneration(ctx, plan); err != nil {
			clear(document)
			return errors.New("DKIM2 retention deletion is uncertain")
		}
		if err := removeRetentionJournal(policy.JournalFile, policy.MaxJournalBytes, document); err != nil {
			clear(document)
			return err
		}
		clear(document)
	}
	return nil
}
