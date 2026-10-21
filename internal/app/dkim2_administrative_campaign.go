package app

import (
	"context"
	"errors"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// publishAdministrativeSuccessor keeps explicit profile changes on the configured native authority contract.
func (m *DKIM2Manager) publishAdministrativeSuccessor(ctx context.Context, expected uint64, candidate *dkim2model.Generation) error {
	if !m.cfg.DKIM2.RotationEnabled || expected == 0 {
		return m.repository.Publish(ctx, expected, candidate)
	}
	if m.campaignRepository == nil || candidate == nil || candidate.Number() != expected+1 {
		return errors.New("native DKIM2 administrative publication is unavailable")
	}
	operation, err := dkim2model.GenerateOperationID(m.random)
	if err != nil {
		return errors.New("native DKIM2 administrative operation identity is unavailable")
	}
	metadata, err := dkim2model.NewCandidateMetadataForOperation(operation, expected, candidate)
	if err != nil {
		return errors.New("native DKIM2 administrative commitment is invalid")
	}
	prepared, err := m.campaignRepository.StageCampaign(ctx, candidate, metadata)
	if err != nil {
		if prepared != nil {
			_ = prepared.Close()
		}
		prepared, err = m.campaignRepository.LoadPending(ctx, candidate.Number(), m.cfg.DKIM2.HistoryLimit)
	}
	if err != nil || !campaignPreparedMatches(prepared, candidate, metadata) {
		if prepared != nil {
			_ = prepared.Close()
		}
		return errors.New("native DKIM2 administrative staging outcome is uncertain")
	}
	defer func() { _ = prepared.Close() }()
	if prepared.ObservedCurrent() != expected {
		return errors.New("native DKIM2 administrative source changed before activation")
	}
	if err := m.campaignRepository.CommitCampaignAndSwitch(ctx, prepared); err != nil {
		observed, readErr := m.campaignRepository.LoadPending(ctx, candidate.Number(), m.cfg.DKIM2.HistoryLimit)
		if observed != nil {
			defer func() { _ = observed.Close() }()
		}
		if readErr != nil || !campaignPreparedMatches(observed, candidate, metadata) || observed.ObservedCurrent() != candidate.Number() {
			return errors.New("native DKIM2 administrative activation outcome is uncertain")
		}
	}
	return nil
}
