package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type lifecycleMutationFence struct{ token chan struct{} }

func newLifecycleMutationFence() *lifecycleMutationFence {
	fence := &lifecycleMutationFence{token: make(chan struct{}, 1)}
	fence.token <- struct{}{}
	return fence
}

func (f *lifecycleMutationFence) acquire(ctx context.Context) (func(), error) {
	if f == nil || ctx == nil {
		return nil, errors.New("DKIM2 lifecycle mutation fence is unavailable")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.token:
		return func() { f.token <- struct{}{} }, nil
	}
}

var dkim2LifecycleMutations = newLifecycleMutationFence()

type dkim2DNSUpdater interface {
	AddDKIMKey(zone, selectorName, content, subdomain string) error
}

type dkim2RotationPublisher interface {
	PublishIfAbsent(context.Context, string, dnsupdate.ExpectedTXT) (dnsupdate.PublishResult, error)
}

type dkim2RotationProof interface {
	ProveAll(context.Context, []dnsupdate.ExpectedTXT) error
}

type dkim2PresenceObserver interface {
	ObserveChannels(context.Context, dnsupdate.ExpectedTXT) (dnsupdate.PresenceObservation, error)
}

type dkim2RotationRetirer interface {
	Observe(context.Context, dnsupdate.ExpectedTXT) (dnsupdate.PresenceState, error)
	DeleteExact(context.Context, string, dnsupdate.ExpectedTXT) (dnsupdate.DeleteResult, error)
}

// DKIM2Manager owns one invocation of the immutable native DKIM2 mode.
type DKIM2Manager struct {
	cfg                  *config.Config
	opts                 *cli.Options
	repository           dkim2store.GenerationRepository
	rotationRepository   dkim2store.RotationRepository
	ldap                 *ldapstore.Client
	dns                  dkim2DNSUpdater
	lookupTXT            func(string) ([]string, error)
	random               io.Reader
	in                   io.Reader
	out                  io.Writer
	newRotationPublisher func(*config.Config) (dkim2RotationPublisher, error)
	newRotationProof     func(*config.Config) (dkim2RotationProof, error)
	newPresenceObserver  func(*config.Config) (dkim2PresenceObserver, error)
	newRotationRetirer   func(*config.Config) (dkim2RotationRetirer, error)
	now                  func() time.Time
	newLifecycleContext  func(time.Duration) (context.Context, context.CancelFunc)
}

// NewDKIM2Manager constructs only the native DKIM2 repository and its optional DNS writer.
func NewDKIM2Manager(cfg *config.Config, opts *cli.Options) (*DKIM2Manager, error) {
	if cfg == nil || opts == nil {
		return nil, errors.New("DKIM2 configuration and options are required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateForMode(types.ModeDKIM2); err != nil {
		return nil, err
	}
	ldapClient, err := ldapstore.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	repository, err := dkim2store.NewLDAPRepository(ldapClient)
	if err != nil {
		_ = ldapClient.Close()
		return nil, err
	}
	manager := &DKIM2Manager{
		cfg: cfg, opts: opts, repository: repository, rotationRepository: repository, ldap: ldapClient,
		lookupTXT: net.LookupTXT, random: rand.Reader, in: os.Stdin, out: os.Stdout,
		newRotationPublisher: func(cfg *config.Config) (dkim2RotationPublisher, error) {
			return dnsupdate.NewRotationPublisher(cfg)
		},
		newRotationProof: func(cfg *config.Config) (dkim2RotationProof, error) {
			return dnsupdate.NewProofClient(cfg)
		},
		newPresenceObserver: func(cfg *config.Config) (dkim2PresenceObserver, error) {
			return dnsupdate.NewPresenceClient(cfg)
		},
		newRotationRetirer: func(cfg *config.Config) (dkim2RotationRetirer, error) {
			return dnsupdate.NewRotationRetirer(cfg)
		},
		now: func() time.Time { return time.Now().UTC() },
		newLifecycleContext: func(timeout time.Duration) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
	}
	if opts.UpdateDNS {
		if !cfg.AuthenticatedDNSUpdatesConfigured() {
			_ = ldapClient.Close()
			return nil, errors.New("DKIM2 DNS update requires a nameserver, positive TTL, and complete TSIG configuration")
		}
	}
	deferredLifecycleDNS := opts.Rotate || opts.Auto || opts.RetireGenerationSet || opts.RollbackFromGenerationSet
	if opts.UpdateDNS && !opts.DryRun && !deferredLifecycleDNS {
		manager.dns, err = dnsupdate.New(cfg)
		if err != nil {
			_ = ldapClient.Close()
			return nil, err
		}
	}
	return manager, nil
}

// Close releases the selected LDAP transport without retaining protected material.
func (m *DKIM2Manager) Close() error {
	if m == nil || m.ldap == nil {
		return nil
	}
	return m.ldap.Close()
}

// Run rejects legacy lifecycle semantics before dispatching one native command.
func (m *DKIM2Manager) Run() (*RunResult, error) {
	if m == nil || m.opts == nil || m.repository == nil {
		return nil, errors.New("DKIM2 manager is unavailable")
	}
	if err := m.validateCommand(); err != nil {
		return nil, err
	}
	lifecycle := m.opts.Rotate || m.opts.Auto || m.opts.RetireGenerationSet || m.opts.RollbackFromGenerationSet || m.opts.Observe
	ctx := context.Background()
	cancel := func() {}
	if lifecycle {
		timeout := time.Duration(m.cfg.DKIM2.RunTimeoutSeconds) * time.Second
		if timeout <= 0 {
			return nil, errors.New("DKIM2 lifecycle deadline is invalid")
		}
		if m.newLifecycleContext != nil {
			ctx, cancel = m.newLifecycleContext(timeout)
		} else {
			ctx, cancel = context.WithTimeout(ctx, timeout)
		}
		if ctx == nil || cancel == nil {
			return nil, errors.New("DKIM2 lifecycle deadline is unavailable")
		}
	}
	defer cancel()
	ctx = dkim2store.WithLifecycleWorkBudget(ctx, m.cfg.DKIM2.HistoryLimit)
	if (m.opts.Create || m.opts.Active || m.opts.Rotate || m.opts.Auto ||
		m.opts.RetireGenerationSet || m.opts.RollbackFromGenerationSet) && !m.opts.DryRun {
		if err := m.authorizeWrite(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("DKIM2 lifecycle deadline expired")
	}
	result := &RunResult{}
	if m.opts.Rotate || m.opts.Auto || m.opts.RetireGenerationSet || m.opts.RollbackFromGenerationSet {
		release, err := dkim2LifecycleMutations.acquire(ctx)
		if err != nil {
			return nil, errors.New("DKIM2 lifecycle deadline expired while waiting for the mutation fence")
		}
		defer release()
	}
	switch {
	case m.opts.List:
		return result, m.list(ctx)
	case m.opts.Create:
		return result, m.create(ctx)
	case m.opts.Active:
		return result, m.activate(ctx)
	case m.opts.TestKey:
		return result, m.testKeys(ctx)
	case m.opts.PrintDNS:
		return result, m.printDNS(ctx)
	case m.opts.Observe:
		return result, m.observeLifecycle(ctx, result)
	case m.opts.Rotate, m.opts.Auto, m.opts.RetireGenerationSet, m.opts.RollbackFromGenerationSet:
		switch {
		case m.opts.Rotate:
			return result, m.rotate(ctx, result)
		case m.opts.Auto:
			return result, m.autoRotate(ctx, result)
		case m.opts.RetireGenerationSet:
			return result, m.retire(ctx, result)
		default:
			return result, m.forwardRollback(ctx, result)
		}
	default:
		return result, nil
	}
}

// validateCommand enforces the deliberately narrow native lifecycle surface.
func (m *DKIM2Manager) validateCommand() error {
	o := m.opts
	if o.Delete || o.ForceDelete || o.Age != nil || o.AddMissing || o.AddNew ||
		o.MaxInitial != 0 || o.MaxRevokedSet ||
		o.ExpireAfter != nil || o.DeleteDelay != nil {
		return errors.New("requested legacy lifecycle operation is unsupported in dkim2 mode")
	}
	if o.ForceActive {
		return errors.New("--force-active is forbidden in dkim2 mode; fresh exact DNS proof is required")
	}
	if o.AcceptAnyDomain {
		return errors.New("--accept-any-domain is unsupported in dkim2 mode")
	}
	if o.UpdateDNS && !o.Create && !o.Rotate && !o.Auto && !o.RetireGenerationSet && !o.RollbackFromGenerationSet {
		return errors.New("--update-dns requires a DKIM2 DNS lifecycle command")
	}
	domains, err := canonicalUnique(o.Domains, dkim2model.CanonicalDomain)
	if err != nil {
		return fmt.Errorf("invalid DKIM2 domain filter: %w", err)
	}
	selectors, err := canonicalUnique(o.Selectors, dkim2model.CanonicalSelector)
	if err != nil {
		return fmt.Errorf("invalid DKIM2 selector filter: %w", err)
	}
	if len(domains) == 1 {
		for _, selectorName := range selectors {
			if err := dkim2model.ValidateDomainSelector(domains[0], selectorName); err != nil {
				return errors.New("DKIM2 domain and selector form an invalid DNS owner")
			}
		}
	}
	if o.Create {
		algorithms, err := m.algorithms()
		if err != nil {
			return err
		}
		for _, algorithm := range algorithms {
			if algorithm == dkim2model.AlgorithmRSASHA256 &&
				(o.Size < dkim2model.MinRSABits || o.Size > dkim2model.MaxRSABits || o.Size%8 != 0) {
				return fmt.Errorf("DKIM2 RSA size must be a multiple of 8 between %d and %d",
					dkim2model.MinRSABits, dkim2model.MaxRSABits)
			}
		}
	}
	if o.Rotate {
		if len(domains) != 1 || len(selectors) != 0 || !o.UpdateDNS || o.ForceActive || o.AcceptAnyDomain {
			return errors.New("DKIM2 rotation requires one --domain and --update-dns and forbids selector and force scope")
		}
	}
	if o.Observe {
		if len(domains) != 1 || len(selectors) != 0 || o.UpdateDNS || o.ResumeGenerationSet || o.PrepareOnly || o.KeyType != "" {
			return errors.New("DKIM2 observation requires one --domain and forbids DNS mutation and continuation controls")
		}
	}
	if o.Auto {
		if len(domains) != 0 || len(selectors) != 0 || !o.UpdateDNS || !m.cfg.DKIM2.RotationEnabled || o.KeyType != "" {
			return errors.New("DKIM2 automatic rotation requires rotation_enabled and --update-dns without explicit scope")
		}
	}
	if o.RetireGenerationSet {
		if len(domains) != 1 || len(selectors) != 0 || !o.UpdateDNS || !o.AllRetirementAttestations() || o.KeyType != "" {
			return errors.New("DKIM2 retirement requires one domain, DNS update, and every operator attestation")
		}
	}
	if o.RollbackFromGenerationSet {
		if len(domains) != 1 || len(selectors) != 0 || !o.UpdateDNS || o.KeyType != "" {
			return errors.New("DKIM2 forward rollback requires one domain and --update-dns")
		}
	}
	return nil
}

// authorizeWrite requires an explicit noninteractive grant or an affirmative prompt.
func (m *DKIM2Manager) authorizeWrite(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.New("DKIM2 lifecycle deadline expired before authorization")
	}
	if m.opts.Yes {
		return nil
	}
	if !m.opts.Interactive {
		return errConfirmationRequired
	}
	if _, err := fmt.Fprint(m.out, "Authorize this DKIM2 lifecycle mutation? (y/N): "); err != nil {
		return fmt.Errorf("write confirmation prompt: %w", err)
	}
	line, err := bufio.NewReader(m.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if err := ctx.Err(); err != nil {
		return errors.New("DKIM2 lifecycle deadline expired during authorization")
	}
	if answer != "y" && answer != "yes" {
		return errConfirmationRequired
	}
	return nil
}

// list prints only bounded public state from the current generation.
func (m *DKIM2Manager) list(ctx context.Context) error {
	generation, err := m.repository.LoadCurrent(ctx)
	if err != nil {
		return err
	}
	if generation == nil {
		_, err = fmt.Fprintln(m.out, "DKIM2 dataset is empty")
		return err
	}
	defer func() { _ = generation.Close() }()
	if _, err := fmt.Fprintf(m.out, "DKIM2 generation %d\n", generation.Number()); err != nil {
		return err
	}
	profiles := generation.Profiles()
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].SigningDomain() == profiles[j].SigningDomain() {
			return profiles[i].ID() < profiles[j].ID()
		}
		return profiles[i].SigningDomain() < profiles[j].SigningDomain()
	})
	for _, profile := range profiles {
		if !matchesString(m.opts.Domains, profile.SigningDomain()) {
			continue
		}
		credentials := credentialsForProfile(generation, profile.ID())
		for _, credential := range credentials {
			if !matchesString(m.opts.Selectors, credential.Selector()) {
				continue
			}
			if _, err := fmt.Fprintf(m.out, "%s selector=%s algorithm=%s status=%s\n",
				profile.SigningDomain(), credential.Selector(), credential.Algorithm(), profile.Status()); err != nil {
				return err
			}
		}
	}
	return nil
}

// create builds and publishes one complete successor containing new disabled profiles.
func (m *DKIM2Manager) create(ctx context.Context) error {
	current, err := m.repository.LoadCurrent(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		defer func() { _ = current.Close() }()
	}
	history, err := m.loadMutationHistory(ctx, current)
	if err != nil {
		return err
	}
	expected := uint64(0)
	if current != nil {
		expected = current.Number()
	}
	if expected == ^uint64(0) {
		return errors.New("DKIM2 generation counter is exhausted")
	}
	builder, err := newSuccessorBuilder(current, expected+1)
	if err != nil {
		return err
	}
	defer func() { _ = builder.Close() }()

	domains, err := canonicalUnique(m.opts.Domains, dkim2model.CanonicalDomain)
	if err != nil {
		return fmt.Errorf("invalid DKIM2 domain: %w", err)
	}
	algorithms, err := m.algorithms()
	if err != nil {
		return err
	}
	if len(m.opts.Selectors) > 0 && len(domains) != 1 {
		return errors.New("explicit selectors require exactly one --domain in dkim2 mode")
	}
	if len(m.opts.Selectors) > 0 && len(m.opts.Selectors) != len(algorithms) {
		return errors.New("the number of selectors must match the number of DKIM2 algorithms")
	}
	usedSelectors := map[string]struct{}{}
	usedIDs := map[string]struct{}{}
	if current != nil {
		for _, credential := range current.Credentials() {
			usedSelectors[credential.Selector()] = struct{}{}
		}
		for _, handle := range current.Handles() {
			usedIDs[handle.ID()] = struct{}{}
		}
		for _, profile := range current.Profiles() {
			usedIDs[profile.ID()] = struct{}{}
		}
	}

	type plannedDNS struct {
		domain, selector, content string
	}
	planned := make([]plannedDNS, 0, len(domains)*len(algorithms))
	for _, domain := range domains {
		if current != nil && bindingExists(current, m.cfg.DKIM2.TenantID, domain, dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse)) {
			return fmt.Errorf("DKIM2 policy binding already exists for %s", domain)
		}
		profileID, err := m.uniqueIdentifier("profile", usedIDs)
		if err != nil {
			return err
		}
		profile, err := dkim2model.NewProfile(
			expected+1, profileID, domain, dkim2model.RecordStatusDisabled,
			time.Time{}, time.Time{},
		)
		if err != nil {
			return err
		}
		credentials := make([]dkim2model.Credential, 0, len(algorithms))
		materials := make([]*dkim2model.KeyMaterial, 0, len(algorithms))
		for index, algorithm := range algorithms {
			selectorName := ""
			if len(m.opts.Selectors) > 0 {
				selectorName, err = exactCanonical(m.opts.Selectors[index], dkim2model.CanonicalSelector)
			} else {
				selectorName, err = m.uniqueSelector(usedSelectors, history)
			}
			if err != nil {
				closeMaterials(materials)
				return fmt.Errorf("invalid DKIM2 selector: %w", err)
			}
			if _, duplicate := usedSelectors[selectorName]; duplicate {
				closeMaterials(materials)
				return fmt.Errorf("DKIM2 selector %q already exists", selectorName)
			}
			historicalSelector, historyErr := history.SelectorUsed(selectorName)
			if historyErr != nil || historicalSelector {
				closeMaterials(materials)
				return errors.New("DKIM2 selector conflicts with retained history")
			}
			usedSelectors[selectorName] = struct{}{}
			handleID, identifierErr := m.uniqueHistoricalIdentifier("key", usedIDs, history.HandleUsed)
			if identifierErr != nil {
				closeMaterials(materials)
				return identifierErr
			}
			pair, pairErr := dkim2model.GenerateKeyPair(algorithm, m.opts.Size, m.random)
			if pairErr != nil {
				closeMaterials(materials)
				return pairErr
			}
			publicSPKI := pair.PublicSPKIDER()
			credential, credentialErr := dkim2model.NewCredential(
				expected+1, profileID, selectorName, algorithm, publicSPKI, handleID,
			)
			clear(publicSPKI)
			material, materialErr := dkim2model.NewKeyMaterial(
				expected+1, m.cfg.DKIM2.TenantID, domain,
				dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse), handleID, pair,
			)
			_ = pair.Close()
			if credentialErr != nil || materialErr != nil {
				if material != nil {
					_ = material.Close()
				}
				closeMaterials(materials)
				return errors.Join(credentialErr, materialErr)
			}
			credentials = append(credentials, credential)
			materials = append(materials, material)
			planned = append(planned, plannedDNS{
				domain: domain, selector: selectorName, content: dnsRecord(credential),
			})
		}
		policy, err := dkim2model.NewPolicy(
			expected+1, m.cfg.DKIM2.TenantID, domain,
			dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse), profileID,
			dkim2model.RecordStatusDisabled, dkim2model.RolloutOff,
			dkim2model.CompatibilityStrict, m.cfg.DKIM2.FeedbackRouteID,
		)
		if err == nil {
			err = builder.AddProfileWithKeys(profile, credentials, policy, materials)
		}
		closeMaterials(materials)
		if err != nil {
			return err
		}
	}
	candidate, err := builder.Build()
	if err != nil {
		return err
	}
	defer func() { _ = candidate.Close() }()
	if m.opts.DryRun {
		_, err = fmt.Fprintf(m.out, "dry-run: validated complete DKIM2 generation %d with %d new profile(s); no LDAP or DNS writes\n", candidate.Number(), len(domains))
		return err
	}
	if err := m.repository.Publish(ctx, expected, candidate); err != nil {
		return err
	}
	if m.opts.UpdateDNS {
		if m.dns == nil {
			return errors.New("DKIM2 DNS updater is unavailable")
		}
		for _, record := range planned {
			if err := m.dns.AddDKIMKey(record.domain, record.selector, record.content, ""); err != nil {
				return fmt.Errorf("publish inactive DKIM2 DNS record for %s: %w", record.domain, err)
			}
		}
	}
	_, err = fmt.Fprintf(m.out, "published inactive DKIM2 generation %d with %d new profile(s)\n", candidate.Number(), len(domains))
	return err
}

// activate verifies every credential in the selected profile before publishing its policy.
func (m *DKIM2Manager) activate(ctx context.Context) error {
	if len(m.opts.Domains) != 1 || len(m.opts.Selectors) != 1 {
		return errors.New("DKIM2 activation requires exactly one --domain and one --selectorname")
	}
	domain, err := exactCanonical(m.opts.Domains[0], dkim2model.CanonicalDomain)
	if err != nil {
		return err
	}
	selectorName, err := exactCanonical(m.opts.Selectors[0], dkim2model.CanonicalSelector)
	if err != nil {
		return err
	}
	current, err := m.repository.LoadCurrent(ctx)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("DKIM2 dataset is empty")
	}
	defer func() { _ = current.Close() }()
	if _, err := m.loadMutationHistory(ctx, current); err != nil {
		return err
	}
	credential, found := current.CredentialByDomainSelector(domain, selectorName)
	if !found {
		return errors.New("exact DKIM2 credential was not found")
	}
	profile, found := current.ProfileByID(credential.ProfileID())
	if !found {
		return errors.New("DKIM2 profile relationship is invalid")
	}
	policy, found := exactPolicy(current, m.cfg.DKIM2.TenantID, domain, dkim2model.ProfileUse(m.cfg.DKIM2.ProfileUse))
	if !found || policy.ProfileID() != profile.ID() {
		return errors.New("exact DKIM2 policy binding was not found")
	}
	for _, related := range credentialsForProfile(current, profile.ID()) {
		if err := m.verifyCredential(related, domain); err != nil {
			return err
		}
	}
	if current.Number() == ^uint64(0) {
		return errors.New("DKIM2 generation counter is exhausted")
	}
	next := current.Number() + 1
	builder, err := current.NextBuilder(next, dkim2model.DatasetStateStaging)
	if err != nil {
		return err
	}
	defer func() { _ = builder.Close() }()
	from, until, present := profile.ValidityWindow()
	if !present {
		from, until = time.Time{}, time.Time{}
	}
	activeProfile, err := dkim2model.NewProfile(next, profile.ID(), domain, dkim2model.RecordStatusActive, from, until)
	if err != nil {
		return err
	}
	activePolicy, err := dkim2model.NewPolicy(
		next, policy.TenantID(), domain, policy.Use(), profile.ID(),
		dkim2model.RecordStatusActive, dkim2model.Rollout(m.cfg.DKIM2.Rollout),
		policy.Compatibility(), policy.FeedbackRouteID(),
	)
	if err != nil {
		return err
	}
	if err := builder.ReplaceProfile(activeProfile); err != nil {
		return err
	}
	if err := builder.UpsertPolicy(activePolicy); err != nil {
		return err
	}
	candidate, err := builder.Build()
	if err != nil {
		return err
	}
	defer func() { _ = candidate.Close() }()
	if m.opts.DryRun {
		_, err = fmt.Fprintf(m.out, "dry-run: DNS verified and DKIM2 generation %d validated; no LDAP write\n", next)
		return err
	}
	if err := m.repository.Publish(ctx, current.Number(), candidate); err != nil {
		return err
	}
	_, err = fmt.Fprintf(m.out, "published active DKIM2 generation %d for %s\n", next, domain)
	return err
}

// testKeys performs fresh exact DNS checks for the requested public credentials.
func (m *DKIM2Manager) testKeys(ctx context.Context) error {
	generation, err := m.repository.LoadCurrent(ctx)
	if err != nil {
		return err
	}
	if generation == nil {
		return errors.New("DKIM2 dataset is empty")
	}
	defer func() { _ = generation.Close() }()
	matched := 0
	for _, credential := range generation.Credentials() {
		profile, found := generation.ProfileByID(credential.ProfileID())
		if !found {
			return errors.New("DKIM2 profile relationship is invalid")
		}
		if len(m.opts.Domains) > 0 && !matchesString(m.opts.Domains, profile.SigningDomain()) {
			continue
		}
		if len(m.opts.Selectors) > 0 && !matchesString(m.opts.Selectors, credential.Selector()) {
			continue
		}
		matched++
		if err := m.verifyCredential(credential, profile.SigningDomain()); err != nil {
			return err
		}
	}
	if matched == 0 {
		return errors.New("no exact DKIM2 credential matched")
	}
	_, err = fmt.Fprintf(m.out, "verified %d DKIM2 DNS credential(s)\n", matched)
	return err
}

// printDNS emits only DNS public-key records for selected credentials.
func (m *DKIM2Manager) printDNS(ctx context.Context) error {
	generation, err := m.repository.LoadCurrent(ctx)
	if err != nil {
		return err
	}
	if generation == nil {
		return errors.New("DKIM2 dataset is empty")
	}
	defer func() { _ = generation.Close() }()
	matched := 0
	for _, credential := range generation.Credentials() {
		profile, found := generation.ProfileByID(credential.ProfileID())
		if !found {
			return errors.New("DKIM2 profile relationship is invalid")
		}
		if !matchesString(m.opts.Domains, profile.SigningDomain()) ||
			!matchesString(m.opts.Selectors, credential.Selector()) {
			continue
		}
		matched++
		if _, err := fmt.Fprintf(m.out, "%s._domainkey.%s. IN TXT %s\n",
			credential.Selector(), profile.SigningDomain(), dnsupdate.Make254(dnsRecord(credential))); err != nil {
			return err
		}
	}
	if matched == 0 {
		return errors.New("no exact DKIM2 credential matched")
	}
	return nil
}

// verifyCredential requires one unambiguous strict TXT record matching the credential.
func (m *DKIM2Manager) verifyCredential(credential dkim2model.Credential, domain string) error {
	name := credential.Selector() + "._domainkey." + domain + "."
	records, err := m.lookupTXT(name)
	if err != nil {
		return fmt.Errorf("DKIM2 DNS lookup failed for %s", name)
	}
	if len(records) != 1 {
		return fmt.Errorf("DKIM2 DNS proof for %s is ambiguous", name)
	}
	algorithm, public, err := parseDNSRecord(records[0])
	if err != nil || algorithm != credential.Algorithm() ||
		!credential.MatchesDNSPublicKeyBytes(public) {
		return fmt.Errorf("DKIM2 DNS proof for %s does not match LDAP", name)
	}
	return nil
}

func (m *DKIM2Manager) algorithms() ([]dkim2model.Algorithm, error) {
	switch m.opts.EffectiveKeyType(m.cfg.KeyType) {
	case types.DKIMKeyTypeRSA:
		return []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256}, nil
	case types.DKIMKeyTypeED25519:
		return []dkim2model.Algorithm{dkim2model.AlgorithmEd25519SHA256}, nil
	case types.DKIMKeyTypeBoth:
		return []dkim2model.Algorithm{dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256}, nil
	default:
		return nil, errors.New("unsupported DKIM2 key type")
	}
}

func newSuccessorBuilder(current *dkim2model.Generation, number uint64) (*dkim2model.Builder, error) {
	if current == nil {
		return dkim2model.NewBuilder(number, dkim2model.DatasetStateStaging)
	}
	return current.NextBuilder(number, dkim2model.DatasetStateStaging)
}

func (m *DKIM2Manager) uniqueIdentifier(prefix string, used map[string]struct{}) (string, error) {
	for range 16 {
		buffer := make([]byte, 12)
		if _, err := io.ReadFull(m.random, buffer); err != nil {
			return "", fmt.Errorf("read DKIM2 identifier randomness: %w", err)
		}
		candidate := prefix + "-" + hex.EncodeToString(buffer)
		clear(buffer)
		if _, exists := used[candidate]; !exists {
			used[candidate] = struct{}{}
			return candidate, nil
		}
	}
	return "", errors.New("could not allocate a unique DKIM2 identifier")
}

func (m *DKIM2Manager) uniqueSelector(used map[string]struct{}, history dkim2store.RetainedHistory) (string, error) {
	for range 16 {
		candidate, err := m.uniqueIdentifier("dkim2", map[string]struct{}{})
		if err != nil {
			return "", err
		}
		historical, historyErr := history.SelectorUsed(candidate)
		if historyErr != nil {
			return "", historyErr
		}
		if _, exists := used[candidate]; !exists && !historical {
			return candidate, nil
		}
	}
	return "", errors.New("could not allocate a unique DKIM2 selector")
}

func (m *DKIM2Manager) uniqueHistoricalIdentifier(prefix string, used map[string]struct{}, historical func(string) (bool, error)) (string, error) {
	for range 16 {
		candidate, err := m.uniqueIdentifier(prefix, map[string]struct{}{})
		if err != nil {
			return "", err
		}
		seen, historyErr := historical(candidate)
		if historyErr != nil {
			return "", historyErr
		}
		if _, exists := used[candidate]; !exists && !seen {
			used[candidate] = struct{}{}
			return candidate, nil
		}
	}
	return "", errors.New("could not allocate a unique historical DKIM2 identifier")
}

func (m *DKIM2Manager) loadMutationHistory(ctx context.Context, current *dkim2model.Generation) (dkim2store.RetainedHistory, error) {
	history, err := m.repository.LoadRetainedHistory(ctx, m.cfg.DKIM2.HistoryLimit)
	if err != nil {
		return dkim2store.RetainedHistory{}, err
	}
	if !history.Complete {
		return dkim2store.RetainedHistory{}, errors.New("DKIM2 retained history is incomplete")
	}
	if current == nil {
		if len(history.Roots) != 0 {
			return dkim2store.RetainedHistory{}, errors.New("DKIM2 empty dataset has retained generation roots")
		}
		return history, nil
	}
	if !retainedRootsContiguous(history.Roots) {
		return dkim2store.RetainedHistory{}, errors.New("DKIM2 retained history roots are not contiguous")
	}
	currentFound := false
	for _, root := range history.Roots {
		if root.Number > current.Number() {
			return dkim2store.RetainedHistory{}, errors.New("DKIM2 non-current higher generation requires repair")
		}
		if root.State != dkim2model.DatasetStateCommitted {
			return dkim2store.RetainedHistory{}, errors.New("DKIM2 non-committed retained generation requires repair")
		}
		if root.Number == current.Number() {
			currentFound = true
		}
	}
	if !currentFound {
		return dkim2store.RetainedHistory{}, errors.New("DKIM2 current generation is absent from retained history")
	}
	return history, nil
}

// retainedRootsContiguous validates an order-independent complete 1..maximum root set.
func retainedRootsContiguous(roots []dkim2store.GenerationRoot) bool {
	if len(roots) == 0 {
		return false
	}
	seen := make(map[uint64]struct{}, len(roots))
	maximum := uint64(0)
	for _, root := range roots {
		if root.Number == 0 {
			return false
		}
		if _, duplicate := seen[root.Number]; duplicate {
			return false
		}
		seen[root.Number] = struct{}{}
		if root.Number > maximum {
			maximum = root.Number
		}
	}
	if maximum != uint64(len(roots)) {
		return false
	}
	for number := uint64(1); number <= maximum; number++ {
		if _, found := seen[number]; !found {
			return false
		}
	}
	return true
}

func canonicalUnique(values []string, canonicalize func(string) (string, error)) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		canonical, err := exactCanonical(value, canonicalize)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[canonical]; duplicate {
			return nil, errors.New("duplicate canonical value")
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func exactCanonical(value string, canonicalize func(string) (string, error)) (string, error) {
	canonical, err := canonicalize(value)
	if err != nil || canonical != value {
		return "", dkim2model.ErrInvalid
	}
	return canonical, nil
}

func credentialsForProfile(generation *dkim2model.Generation, profileID string) []dkim2model.Credential {
	result := make([]dkim2model.Credential, 0, 2)
	for _, credential := range generation.Credentials() {
		if credential.ProfileID() == profileID {
			result = append(result, credential)
		}
	}
	return result
}

func exactPolicy(generation *dkim2model.Generation, tenant, domain string, use dkim2model.ProfileUse) (dkim2model.Policy, bool) {
	var result dkim2model.Policy
	count := 0
	for _, policy := range generation.Policies() {
		if policy.TenantID() == tenant && policy.SigningDomain() == domain && policy.Use() == use {
			result = policy
			count++
		}
	}
	return result, count == 1
}

func bindingExists(generation *dkim2model.Generation, tenant, domain string, use dkim2model.ProfileUse) bool {
	_, found := exactPolicy(generation, tenant, domain, use)
	return found
}

func matchesString(filter []string, candidate string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, value := range filter {
		if value == candidate {
			return true
		}
	}
	return false
}

func dnsRecord(credential dkim2model.Credential) string {
	keyType := "rsa"
	if credential.Algorithm() == dkim2model.AlgorithmEd25519SHA256 {
		keyType = "ed25519"
	}
	return "v=DKIM1; k=" + keyType + "; h=sha256; p=" +
		base64.StdEncoding.EncodeToString(credential.DNSPublicKeyBytes())
}

func parseDNSRecord(record string) (dkim2model.Algorithm, []byte, error) {
	if record == "" || len(record) > 16<<10 {
		return "", nil, errors.New("malformed DKIM DNS record")
	}
	fields := strings.Split(record, ";")
	values := make(map[string]string, len(fields))
	firstTag := ""
	for index, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" && index == len(fields)-1 {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return "", nil, errors.New("malformed DKIM DNS field")
		}
		name := strings.TrimSpace(parts[0])
		if name != strings.ToLower(name) || !knownDNSRecordTag(name) {
			return "", nil, errors.New("unsupported DKIM DNS field")
		}
		if _, duplicate := values[name]; duplicate {
			return "", nil, errors.New("duplicate DKIM DNS field")
		}
		value := strings.TrimSpace(parts[1])
		if len(value) > 8<<10 || !validDNSGenericValue(value) {
			return "", nil, errors.New("invalid DKIM DNS field value")
		}
		if firstTag == "" {
			firstTag = name
		}
		values[name] = value
	}
	if version, present := values["v"]; present && (firstTag != "v" || version != "DKIM1") {
		return "", nil, errors.New("invalid DKIM DNS version")
	}
	publicValue, present := values["p"]
	if !present || publicValue == "" {
		return "", nil, errors.New("missing or revoked DKIM DNS public key")
	}
	if flags, present := values["t"]; present && !validDNSFlags(flags) {
		return "", nil, errors.New("invalid DKIM DNS flags")
	}
	var algorithm dkim2model.Algorithm
	switch keyType, present := values["k"]; {
	case !present || keyType == "rsa":
		algorithm = dkim2model.AlgorithmRSASHA256
	case keyType == "ed25519":
		algorithm = dkim2model.AlgorithmEd25519SHA256
	default:
		return "", nil, errors.New("unsupported DKIM DNS algorithm")
	}
	public, err := decodeDNSPublicValue(publicValue)
	if err != nil {
		return "", nil, errors.New("noncanonical DKIM DNS public key")
	}
	return algorithm, public, nil
}

// knownDNSRecordTag preserves the closed DNS-04 key-record vocabulary.
func knownDNSRecordTag(name string) bool {
	switch name {
	case "v", "h", "k", "n", "p", "s", "t":
		return true
	default:
		return false
	}
}

// validDNSGenericValue rejects control and non-ASCII bytes before tag-specific parsing.
func validDNSGenericValue(value string) bool {
	for index := range len(value) {
		candidate := value[index]
		if candidate != '\t' && (candidate < 0x20 || candidate > 0x7e) {
			return false
		}
	}
	return true
}

// validDNSFlags validates the optional colon-separated DNS-04 t= vocabulary.
func validDNSFlags(value string) bool {
	if value == "" {
		return false
	}
	for _, raw := range strings.Split(value, ":") {
		if !validDNSHyphenatedWord(strings.Trim(raw, " \t")) {
			return false
		}
	}
	return true
}

// validDNSHyphenatedWord enforces ASCII alphabetic edges and word interiors.
func validDNSHyphenatedWord(value string) bool {
	if value == "" || !asciiAlpha(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if !asciiAlphaNumeric(value[index]) && value[index] != '-' {
			return false
		}
	}
	return true
}

func asciiAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func asciiAlphaNumeric(value byte) bool {
	return asciiAlpha(value) || value >= '0' && value <= '9'
}

// decodeDNSPublicValue accepts DNS-04 optional padding with canonical zero pad bits.
func decodeDNSPublicValue(value string) ([]byte, error) {
	compact := strings.NewReplacer(" ", "", "\t", "").Replace(value)
	if compact == "" || len(compact) > 16<<10 {
		return nil, errors.New("invalid DNS public key")
	}
	var (
		decoded []byte
		err     error
	)
	if strings.Contains(compact, "=") {
		decoded, err = base64.StdEncoding.Strict().DecodeString(compact)
		if err == nil && base64.StdEncoding.EncodeToString(decoded) != compact {
			err = errors.New("noncanonical padded base64")
		}
	} else {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(compact)
		if err == nil && base64.RawStdEncoding.EncodeToString(decoded) != compact {
			err = errors.New("noncanonical unpadded base64")
		}
	}
	if err != nil || len(decoded) == 0 || len(decoded) > 8<<10 {
		clear(decoded)
		return nil, errors.New("invalid DNS public key")
	}
	return decoded, nil
}

func closeMaterials(materials []*dkim2model.KeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}
