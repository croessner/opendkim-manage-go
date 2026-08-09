package dkim2store

import (
	"context"
	"sort"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

type deletionExecutor interface {
	DeleteRequest(*ldap.DelRequest) error
}

// InventoryGenerations fully verifies every bounded generation under one stable current fence.
func (r *LDAPRepository) InventoryGenerations(ctx context.Context) (GenerationInventory, error) {
	if err := validContext(ctx); err != nil || r == nil {
		return GenerationInventory{}, ErrUnavailable
	}
	first, absent, err := r.readCurrentPointer(ctx)
	if err != nil || absent {
		return GenerationInventory{}, ErrConflict
	}
	size := r.limits.HistoryLimit + 1
	result, err := r.search(ctx, r.boundedSearch(
		r.generationsBase, ldap.ScopeSingleLevel, size, "("+attributeObjectClass+"=*)",
		[]string{attributeObjectClass, attributeCN, attributeSchemaVersion, attributeGeneration,
			attributeDatasetState, attributeWasActive, attributeCandidateDigest, attributeOperationID, attributeSourceGeneration},
	))
	if err != nil || result == nil || len(result.Referrals) != 0 || len(result.Entries) > r.limits.HistoryLimit {
		return GenerationInventory{}, ErrUnavailable
	}
	inventory := GenerationInventory{Current: first.generation, Roots: make([]GenerationInventoryRoot, 0, len(result.Entries))}
	seen := make(map[uint64]struct{}, len(result.Entries))
	for _, root := range result.Entries {
		facts, factErr := r.inventoryRoot(ctx, root)
		if factErr != nil {
			return GenerationInventory{}, factErr
		}
		if _, duplicate := seen[facts.Number]; duplicate {
			return GenerationInventory{}, ErrMalformed
		}
		seen[facts.Number] = struct{}{}
		inventory.Roots = append(inventory.Roots, facts)
	}
	sort.Slice(inventory.Roots, func(i, j int) bool { return inventory.Roots[i].Number < inventory.Roots[j].Number })
	if len(inventory.Roots) == 0 || !contiguousInventorySuffix(inventory.Roots) {
		return GenerationInventory{}, ErrMalformed
	}
	currentFound := false
	for _, root := range inventory.Roots {
		if root.Number == first.generation {
			currentFound = root.Complete && root.State == dkim2model.DatasetStateCommitted
		}
	}
	second, secondAbsent, err := r.readCurrentPointer(ctx)
	if err != nil || secondAbsent || second != first || !currentFound {
		return GenerationInventory{}, ErrConflict
	}
	return inventory, nil
}

func (r *LDAPRepository) inventoryRoot(ctx context.Context, root *ldap.Entry) (GenerationInventoryRoot, error) {
	if root == nil {
		return GenerationInventoryRoot{}, ErrMalformed
	}
	generationValues, found := rawAttribute(root, attributeGeneration)
	if !found || len(generationValues) != 1 {
		return GenerationInventoryRoot{}, ErrMalformed
	}
	generation, err := parseGeneration(generationValues[0])
	if err != nil || !sameDN(root.DN, r.generationRoot(generation)) {
		return GenerationInventoryRoot{}, ErrMalformed
	}
	schemaValues, schemaFound := rawAttribute(root, attributeSchemaVersion)
	stateValues, stateFound := rawAttribute(root, attributeDatasetState)
	if !schemaFound || len(schemaValues) != 1 || !stateFound || len(stateValues) != 1 {
		return GenerationInventoryRoot{}, ErrMalformed
	}
	state, err := dkim2model.ParseDatasetState(string(stateValues[0]))
	if err != nil {
		return GenerationInventoryRoot{}, ErrMalformed
	}
	entries, err := r.readGeneration(ctx, generation)
	if err != nil {
		return GenerationInventoryRoot{}, err
	}
	complete, err := mapGeneration(entries, generation, string(state), r.generationRoot(generation), r.limits)
	if err != nil {
		return GenerationInventoryRoot{}, err
	}
	_ = complete.Close()
	var metadata dkim2model.CandidateMetadata
	if string(schemaValues[0]) == dkim2model.SchemaVersionV3 {
		var campaign bool
		metadata, campaign, err = projectCampaignMetadata(entries, r.generationRoot(generation), generation, r.limits)
		if err != nil || !campaign {
			return GenerationInventoryRoot{}, ErrMalformed
		}
	}
	wasActive := false
	if values, present := rawAttribute(root, attributeWasActive); present {
		wasActive = len(values) == 1 && string(values[0]) == "TRUE"
		if !wasActive {
			return GenerationInventoryRoot{}, ErrMalformed
		}
	}
	return GenerationInventoryRoot{Number: generation, Schema: string(schemaValues[0]), State: state,
		WasActive: wasActive, Complete: true, Metadata: metadata}, nil
}

func contiguousInventorySuffix(roots []GenerationInventoryRoot) bool {
	for index, root := range roots {
		if root.Number == 0 || index > 0 && root.Number != roots[index-1].Number+1 {
			return false
		}
	}
	return true
}

// DeleteGeneration removes one exact validated old v3 generation leaf-first and verifies absence.
func (r *LDAPRepository) DeleteGeneration(ctx context.Context, plan GenerationPurgePlan) error {
	return r.deleteGenerationFromPlan(ctx, plan, r)
}

func (r *LDAPRepository) deleteGenerationFromPlan(ctx context.Context, plan GenerationPurgePlan, reader *LDAPRepository) error {
	executor, ok := r.executor.(deletionExecutor)
	if !ok || !plan.valid() || reader == nil {
		return ErrConflict
	}
	generation := plan.Generation()
	pointer, absent, err := reader.readCurrentPointer(ctx)
	if err != nil || absent || pointer.generation != plan.Current() {
		return ErrConflict
	}
	entries, err := reader.readGenerationForDeletion(ctx, generation)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clearSensitiveEntries(entries)
	if !rootMatchesPurgePlan(entries, r.generationRoot(generation), plan, r.limits) {
		return ErrConflict
	}
	sort.Slice(entries, func(i, j int) bool {
		left, _ := ldap.ParseDN(entries[i].DN)
		right, _ := ldap.ParseDN(entries[j].DN)
		return len(left.RDNs) > len(right.RDNs)
	})
	for _, entry := range entries {
		current, currentAbsent, currentErr := reader.readCurrentPointer(ctx)
		if currentErr != nil || currentAbsent || current != pointer {
			return ErrConflict
		}
		request := ldap.NewDelRequest(entry.DN, nil)
		if budget := workBudgetFromContext(ctx); budget.consume(1, ldapDeleteRequestBytes(request), 0) != nil {
			return ErrUnavailable
		}
		deleteErr := executor.DeleteRequest(request)
		gone, observeErr := reader.entryAbsent(ctx, entry.DN)
		if observeErr != nil || !gone {
			if deleteErr != nil {
				return ErrOutcomeUncertain
			}
			return ErrConflict
		}
	}
	final, finalAbsent, err := reader.readCurrentPointer(ctx)
	if err != nil || finalAbsent || final != pointer {
		return ErrConflict
	}
	return nil
}

func rootMatchesPurgePlan(entries []*ldap.Entry, rootDN string, plan GenerationPurgePlan, limits Limits) bool {
	for _, entry := range entries {
		if !sameDN(entry.DN, rootDN) {
			continue
		}
		values, err := exactEntry(entry, rootDN, classDataset,
			[]string{attributeCN, attributeSchemaVersion, attributeGeneration, attributeDatasetState,
				attributeCandidateDigest, attributeOperationID, attributeSourceGeneration, attributeWasActive}, nil, limits)
		if err != nil || string(values[attributeSchemaVersion][0]) != dkim2model.SchemaVersionV3 ||
			string(values[attributeDatasetState][0]) != datasetStateCommitted ||
			string(values[attributeWasActive][0]) != "TRUE" ||
			string(values[attributeCN][0]) != "generation-"+strconv.FormatUint(plan.Generation(), 10) ||
			string(values[attributeGeneration][0]) != strconv.FormatUint(plan.Generation(), 10) {
			return false
		}
		digest := values[attributeCandidateDigest][0]
		source, err := parseGeneration(values[attributeSourceGeneration][0])
		if err != nil {
			return false
		}
		metadata, err := dkim2model.ParseCandidateMetadata(string(values[attributeOperationID][0]),
			source, plan.Generation(), digest)
		return err == nil && metadata.ExactEqual(plan.metadata)
	}
	return false
}

func (r *LDAPRepository) readGenerationForDeletion(ctx context.Context, generation uint64) ([]*ldap.Entry, error) {
	attributes := []string{attributeObjectClass, attributeCN, attributeOU, attributeSchemaVersion,
		attributeGeneration, attributeDatasetState, attributeCandidateDigest, attributeOperationID,
		attributeSourceGeneration, attributeWasActive}
	result, err := r.search(ctx, r.boundedSearch(r.generationRoot(generation), ldap.ScopeWholeSubtree,
		r.limits.MaxGenerationEntries, "("+attributeObjectClass+"=*)", attributes))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, err
	}
	if err != nil || result == nil || len(result.Referrals) != 0 || len(result.Entries) == 0 ||
		len(result.Entries) > r.limits.MaxGenerationEntries {
		return nil, ErrUnavailable
	}
	return result.Entries, nil
}

func (r *LDAPRepository) entryAbsent(ctx context.Context, dn string) (bool, error) {
	result, err := r.search(ctx, r.boundedSearch(dn, ldap.ScopeBaseObject, 1, "("+attributeObjectClass+"=*)", []string{attributeObjectClass}))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return true, nil
	}
	if err != nil {
		return false, ErrUnavailable
	}
	return result != nil && len(result.Entries) == 0, nil
}
