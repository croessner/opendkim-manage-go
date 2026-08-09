package dkim2store

import (
	"context"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// RoleRepository composes four distinct least-privilege LDAP authorities.
type RoleRepository struct {
	snapshot   *LDAPRepository
	staging    *LDAPRepository
	activation *LDAPRepository
	purge      *LDAPRepository
}

var _ CampaignRepository = (*RoleRepository)(nil)

// NewRoleRepository requires four repositories over one exact dataset base and limit contract.
func NewRoleRepository(snapshot, staging, activation, purge *LDAPRepository) (*RoleRepository, error) {
	if snapshot == nil || staging == nil || activation == nil || purge == nil ||
		snapshot.baseDN != staging.baseDN || snapshot.baseDN != activation.baseDN || snapshot.baseDN != purge.baseDN ||
		snapshot.limits != staging.limits || snapshot.limits != activation.limits || snapshot.limits != purge.limits {
		return nil, ErrUnavailable
	}
	return &RoleRepository{snapshot: snapshot, staging: staging, activation: activation, purge: purge}, nil
}

func (r *RoleRepository) LoadCurrent(ctx context.Context) (*dkim2model.Generation, error) {
	return r.snapshot.LoadCurrent(ctx)
}

func (r *RoleRepository) LoadRetainedHistory(ctx context.Context, limit int) (RetainedHistory, error) {
	return r.snapshot.LoadRetainedHistory(ctx, limit)
}

func (r *RoleRepository) LoadRetainedGeneration(ctx context.Context, generation uint64, limit int) (*dkim2model.Generation, error) {
	return r.snapshot.LoadRetainedGeneration(ctx, generation, limit)
}

func (r *RoleRepository) LoadGenerationCreatedAt(ctx context.Context, generation uint64) (time.Time, error) {
	return r.snapshot.LoadGenerationCreatedAt(ctx, generation)
}

func (r *RoleRepository) LoadCurrentActivation(ctx context.Context) (CurrentActivation, error) {
	return r.snapshot.LoadCurrentActivation(ctx)
}

func (r *RoleRepository) Publish(ctx context.Context, expected uint64, candidate *dkim2model.Generation) error {
	if candidate == nil || candidate.Number() != expected+1 || candidate.State() != dkim2model.DatasetStateStaging {
		return ErrMalformed
	}
	if expected == 0 {
		if err := r.activation.prepareBootstrap(ctx, candidate.Number()); err != nil {
			return err
		}
	} else {
		current, err := r.snapshot.LoadCurrent(ctx)
		if err != nil || current == nil {
			return ErrConflict
		}
		number := current.Number()
		_ = current.Close()
		if number != expected {
			return ErrConflict
		}
	}
	if err := r.staging.addCandidate(ctx, candidate); err != nil {
		return err
	}
	if err := r.snapshot.validateReadback(ctx, candidate); err != nil {
		return err
	}
	if err := r.staging.commitGeneration(ctx, candidate.Number()); err != nil {
		return err
	}
	return r.activation.switchCurrent(ctx, expected, candidate.Number())
}

func (r *RoleRepository) Stage(ctx context.Context, candidate *dkim2model.Generation, limit int) (*PreparedGeneration, error) {
	return r.staging.stageWithReader(ctx, candidate, limit, nil, r.snapshot)
}

func (r *RoleRepository) StageCampaign(ctx context.Context, candidate *dkim2model.Generation, metadata dkim2model.CandidateMetadata) (*PreparedGeneration, error) {
	if metadata.ValidateCandidate(candidate) != nil {
		return nil, ErrMalformed
	}
	return r.staging.stageWithReader(ctx, candidate, r.snapshot.limits.HistoryLimit, &metadata, r.snapshot)
}

func (r *RoleRepository) LoadPending(ctx context.Context, candidate uint64, limit int) (*PreparedGeneration, error) {
	return r.snapshot.LoadPending(ctx, candidate, limit)
}

func (r *RoleRepository) CommitAndSwitch(ctx context.Context, candidate uint64, limit int) error {
	prepared, err := r.snapshot.LoadPending(ctx, candidate, limit)
	if err != nil {
		return err
	}
	defer func() { _ = prepared.Close() }()
	if prepared.ObservedCurrent() == candidate {
		return nil
	}
	value, err := prepared.Generation()
	if err != nil {
		return err
	}
	state := value.State()
	_ = value.Close()
	if state == dkim2model.DatasetStateStaging {
		if err := r.staging.commitGeneration(ctx, candidate); err != nil {
			return err
		}
	}
	if committed, err := r.snapshot.loadExactGeneration(ctx, candidate, dkim2model.DatasetStateCommitted); err != nil {
		return err
	} else {
		_ = committed.Close()
	}
	if err := r.activation.switchCurrent(ctx, prepared.ExpectedCurrent(), candidate); err != nil {
		return err
	}
	final, err := r.snapshot.LoadPending(ctx, candidate, limit)
	if err != nil {
		return err
	}
	defer func() { _ = final.Close() }()
	if final.ObservedCurrent() != candidate {
		return ErrOutcomeUncertain
	}
	return nil
}

func (r *RoleRepository) CommitCampaignAndSwitch(ctx context.Context, evidence *PreparedGeneration) error {
	if evidence == nil {
		return ErrMalformed
	}
	metadata, ok := evidence.CampaignMetadata()
	if !ok {
		return ErrMalformed
	}
	prepared, err := r.snapshot.LoadPending(ctx, evidence.CandidateNumber(), r.snapshot.limits.HistoryLimit)
	if err != nil {
		return err
	}
	defer func() { _ = prepared.Close() }()
	observed, ok := prepared.CampaignMetadata()
	if !ok || !metadata.DigestEqual(observed) || observed.SourceGeneration() != prepared.ExpectedCurrent() {
		return ErrConflict
	}
	if prepared.ObservedCurrent() == prepared.CandidateNumber() {
		return nil
	}
	pointer, absent, err := r.snapshot.readCurrentPointer(ctx)
	if err != nil || absent || pointer.generation != prepared.ExpectedCurrent() {
		return ErrConflict
	}
	if pointer.schema == dkim2model.SchemaVersionV3 {
		if err := r.activation.markSourceWasActive(ctx, pointer); err != nil {
			return err
		}
	}
	candidate, err := prepared.Generation()
	if err != nil {
		return err
	}
	state := candidate.State()
	_ = candidate.Close()
	if state == dkim2model.DatasetStateStaging {
		if err := r.staging.commitCampaignGeneration(ctx, observed); err != nil {
			return err
		}
	}
	if committed, err := r.snapshot.LoadPending(ctx, prepared.CandidateNumber(), r.snapshot.limits.HistoryLimit); err != nil {
		return err
	} else {
		_ = committed.Close()
	}
	if err := r.activation.switchCurrentCampaign(ctx, pointer, observed); err != nil {
		return err
	}
	final, err := r.snapshot.LoadPending(ctx, prepared.CandidateNumber(), r.snapshot.limits.HistoryLimit)
	if err != nil {
		return err
	}
	defer func() { _ = final.Close() }()
	finalMetadata, ok := final.CampaignMetadata()
	if !ok || final.ObservedCurrent() != prepared.CandidateNumber() || !finalMetadata.DigestEqual(observed) {
		return ErrOutcomeUncertain
	}
	return nil
}

func (r *RoleRepository) InventoryGenerations(ctx context.Context) (GenerationInventory, error) {
	return r.snapshot.InventoryGenerations(ctx)
}

func (r *RoleRepository) DeleteGeneration(ctx context.Context, plan GenerationPurgePlan) error {
	return r.purge.deleteGenerationFromPlan(ctx, plan, r.snapshot)
}
