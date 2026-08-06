package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type fakeGenerationRepository struct {
	current           *dkim2model.Generation
	loads             int
	publishes         int
	expected          uint64
	published         *dkim2model.Generation
	loadErr           error
	publishErr        error
	publishHook       func()
	historyIncomplete bool
	historyErr        error
	historyLoads      int
	history           *dkim2store.RetainedHistory
}

func (f *fakeGenerationRepository) LoadCurrent(context.Context) (*dkim2model.Generation, error) {
	f.loads++
	if f.loadErr != nil || f.current == nil {
		return nil, f.loadErr
	}
	return f.current.Clone()
}

func (f *fakeGenerationRepository) LoadRetainedHistory(context.Context, int) (dkim2store.RetainedHistory, error) {
	f.historyLoads++
	if f.historyErr != nil {
		return dkim2store.RetainedHistory{}, f.historyErr
	}
	if f.history != nil {
		return *f.history, nil
	}
	if f.historyIncomplete {
		return dkim2store.NewRetainedHistory(nil, false, nil, nil), nil
	}
	if f.current == nil {
		return dkim2store.NewRetainedHistory(nil, true, nil, nil), nil
	}
	var selectors, handles []string
	for _, credential := range f.current.Credentials() {
		selectors = append(selectors, credential.Selector())
	}
	for _, handle := range f.current.Handles() {
		handles = append(handles, handle.ID())
	}
	return dkim2store.NewRetainedHistory([]dkim2store.GenerationRoot{{Number: f.current.Number(), State: f.current.State()}}, true, selectors, handles), nil
}

func TestDKIM2CreateAndActiveRejectIncompleteOrOrphanHistoryBeforeProtectedWork(t *testing.T) {
	for _, command := range []string{"create", "active"} {
		t.Run(command, func(t *testing.T) {
			current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
			repository := &fakeGenerationRepository{current: current, historyIncomplete: true}
			defer repository.close()
			opts := &cli.Options{Size: 2048, DryRun: true}
			if command == "create" {
				opts.Create, opts.Domains, opts.KeyType = true, []string{"new.example.test"}, "ed25519"
			} else {
				opts.Active, opts.Domains, opts.Selectors = true, []string{"example.test"}, []string{"selector-rsa"}
			}
			manager := testDKIM2Manager(repository, opts)
			manager.random = &countingAppReader{}
			manager.lookupTXT = func(string) ([]string, error) {
				t.Fatal("DNS lookup occurred before history preflight")
				return nil, nil
			}
			if _, err := manager.Run(); err == nil || !strings.Contains(err.Error(), "history is incomplete") {
				t.Fatalf("Run() error = %v", err)
			}
		})
	}
}

func TestDKIM2CreateRejectsHigherOrphanRootBeforeRandomness(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	selectors := []string{"selector-rsa", "selector-ed"}
	handles := []string{"handle-secret-marker-rsa", "handle-secret-marker-ed"}
	history := dkim2store.NewRetainedHistory([]dkim2store.GenerationRoot{
		{Number: 1, State: dkim2model.DatasetStateCommitted},
		{Number: 2, State: dkim2model.DatasetStateStaging},
	}, true, selectors, handles)
	repository.history = &history
	manager := testDKIM2Manager(repository, &cli.Options{
		Create: true, Domains: []string{"new.example.test"}, KeyType: "ed25519", Size: 2048, DryRun: true,
	})
	random := &countingAppReader{}
	manager.random = random
	if _, err := manager.Run(); err == nil || !strings.Contains(err.Error(), "higher generation") {
		t.Fatalf("Run() error = %v", err)
	}
	if random.reads != 0 {
		t.Fatalf("higher orphan consumed randomness: %d", random.reads)
	}
}

type countingAppReader struct{ reads int }

func (r *countingAppReader) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("unexpected random read")
}

func (f *fakeGenerationRepository) Publish(_ context.Context, expected uint64, candidate *dkim2model.Generation) error {
	f.publishes++
	f.expected = expected
	if f.publishHook != nil {
		f.publishHook()
	}
	if f.publishErr != nil {
		return f.publishErr
	}
	clone, err := candidate.Clone()
	if err != nil {
		return err
	}
	if f.published != nil {
		_ = f.published.Close()
	}
	f.published = clone
	return nil
}

type fakeDKIM2DNSUpdater struct {
	add func(zone, selectorName, content, subdomain string) error
}

func (f fakeDKIM2DNSUpdater) AddDKIMKey(zone, selectorName, content, subdomain string) error {
	return f.add(zone, selectorName, content, subdomain)
}

func (f *fakeGenerationRepository) close() {
	if f.current != nil {
		_ = f.current.Close()
	}
	if f.published != nil {
		_ = f.published.Close()
	}
}

func TestDKIM2UnsupportedCommandFailsBeforeRepositoryAccess(t *testing.T) {
	for _, opts := range []*cli.Options{
		{Delete: true},
		{Create: true, Domains: []string{"example.test"}, KeyType: "ed25519", MaxInitial: 1},
	} {
		repository := &fakeGenerationRepository{}
		manager := testDKIM2Manager(repository, opts)
		if _, err := manager.Run(); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("Run() error = %v", err)
		}
		if repository.loads != 0 || repository.publishes != 0 {
			t.Fatalf("repository access = loads %d publishes %d", repository.loads, repository.publishes)
		}
	}
}

func TestDKIM2OversizedCompositeOwnerFailsBeforeRepositoryAccess(t *testing.T) {
	domain := strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63)
	repository := &fakeGenerationRepository{}
	manager := testDKIM2Manager(repository, &cli.Options{
		Create: true, Domains: []string{domain}, Selectors: []string{strings.Repeat("s", 63)},
		KeyType: "ed25519", Size: 2048, DryRun: true,
	})
	if _, err := manager.Run(); err == nil {
		t.Fatal("Run() accepted an oversized composite DNS owner")
	}
	if repository.loads != 0 || repository.publishes != 0 {
		t.Fatalf("repository access = loads %d publishes %d", repository.loads, repository.publishes)
	}
}

func TestNewDKIM2ManagerRevalidatesLDAPTransportBoundary(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{
			Mode: types.ModeDKIM2, ExpireAfter: 365, KeyType: "ed25519",
			CNAMESelectorRSAPrefix: "rsa-", CNAMESelectorED25519Prefix: "ed-",
		},
		LDAP: config.LDAPConfig{
			URI:             "ldap://ldap.example.org/ou=dkim2,dc=example,dc=org",
			DomainAttribute: "associatedDomain",
		},
		DKIM2: config.DKIM2Config{
			TenantID: "tenant-test", ProfileUse: "originator", Rollout: "enforce",
			Compatibility: "strict",
		},
	}
	manager, err := NewDKIM2Manager(cfg, &cli.Options{List: true})
	if manager != nil {
		_ = manager.Close()
	}
	if err == nil {
		t.Fatal("NewDKIM2Manager accepted plaintext LDAP without the explicit compatibility exception")
	}
}

func TestDKIM2CreateDryRunBuildsCompleteCandidateWithoutWrite(t *testing.T) {
	repository := &fakeGenerationRepository{}
	opts := &cli.Options{
		Create: true, Domains: []string{"example.test"}, Selectors: []string{"selector-a"},
		KeyType: "ed25519", Size: 2048, DryRun: true,
	}
	manager := testDKIM2Manager(repository, opts)
	var output bytes.Buffer
	manager.out = &output
	if _, err := manager.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repository.loads != 1 || repository.publishes != 0 {
		t.Fatalf("repository access = loads %d publishes %d", repository.loads, repository.publishes)
	}
	if !strings.Contains(output.String(), "no LDAP or DNS writes") || strings.Contains(output.String(), "key-") {
		t.Fatalf("unsafe or incomplete dry-run output: %q", output.String())
	}
}

func TestDKIM2CreatePublishesInactiveCompleteGeneration(t *testing.T) {
	repository := &fakeGenerationRepository{}
	defer repository.close()
	opts := &cli.Options{
		Create: true, Domains: []string{"example.test"},
		Selectors: []string{"selector-rsa", "selector-ed"}, KeyType: "both",
		Size: 2048, Yes: true,
	}
	manager := testDKIM2Manager(repository, opts)
	manager.out = &bytes.Buffer{}
	if _, err := manager.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repository.publishes != 1 || repository.expected != 0 || repository.published == nil {
		t.Fatalf("publication = count %d expected %d generation %v", repository.publishes, repository.expected, repository.published)
	}
	if repository.published.Number() != 1 || repository.published.State() != dkim2model.DatasetStateStaging {
		t.Fatalf("published metadata = generation %d state %q", repository.published.Number(), repository.published.State())
	}
	profiles := repository.published.Profiles()
	policies := repository.published.Policies()
	keyMaterials := repository.published.KeyMaterials()
	defer closeMaterials(keyMaterials)
	if len(profiles) != 1 || profiles[0].Status() != dkim2model.RecordStatusDisabled ||
		len(policies) != 1 || policies[0].Status() != dkim2model.RecordStatusDisabled ||
		policies[0].Rollout() != dkim2model.RolloutOff ||
		len(repository.published.Credentials()) != 2 || len(keyMaterials) != 2 {
		t.Fatalf("published generation is not a complete inactive profile")
	}
}

func TestDKIM2CreatePreservesUnrelatedCurrentProfiles(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusActive, dkim2model.RolloutEnforce)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	manager := testDKIM2Manager(repository, &cli.Options{
		Create: true, Domains: []string{"second.example.test"},
		Selectors: []string{"second-selector"}, KeyType: "ed25519", Size: 2048, Yes: true,
	})
	if _, err := manager.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repository.published == nil || len(repository.published.Profiles()) != 2 ||
		len(repository.published.Credentials()) != 3 {
		t.Fatalf("successor did not preserve the complete prior generation")
	}
	if _, found := repository.published.CredentialByDomainSelector("example.test", "selector-rsa"); !found {
		t.Fatal("unrelated current credential was lost")
	}
}

func TestDKIM2CreatePublishesLDAPBeforeOptionalDNS(t *testing.T) {
	repository := &fakeGenerationRepository{}
	defer repository.close()
	var events []string
	repository.publishHook = func() { events = append(events, "ldap") }
	manager := testDKIM2Manager(repository, &cli.Options{
		Create: true, Domains: []string{"example.test"}, Selectors: []string{"selector-a"},
		KeyType: "ed25519", Size: 2048, Yes: true, UpdateDNS: true,
	})
	manager.dns = fakeDKIM2DNSUpdater{add: func(zone, selectorName, content, subdomain string) error {
		events = append(events, "dns")
		if zone != "example.test" || selectorName != "selector-a" ||
			!strings.Contains(content, "k=ed25519") || subdomain != "" {
			t.Fatalf("unexpected DNS update: %q %q %q %q", zone, selectorName, content, subdomain)
		}
		return nil
	}}
	if _, err := manager.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if strings.Join(events, ",") != "ldap,dns" {
		t.Fatalf("write order = %v", events)
	}
}

func TestDKIM2CreatePublicationConflictDoesNotReportSuccess(t *testing.T) {
	repository := &fakeGenerationRepository{publishErr: errors.New("generation conflict")}
	manager := testDKIM2Manager(repository, &cli.Options{
		Create: true, Domains: []string{"example.test"}, Selectors: []string{"selector-a"},
		KeyType: "ed25519", Size: 2048, Yes: true,
	})
	var output bytes.Buffer
	manager.out = &output
	if _, err := manager.Run(); err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	if strings.Contains(output.String(), "published") {
		t.Fatalf("conflict reported success: %q", output.String())
	}
}

func TestDKIM2ActivationVerifiesEveryProfileCredential(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	manager := testDKIM2Manager(repository, &cli.Options{
		Active: true, Domains: []string{"example.test"}, Selectors: []string{"selector-rsa"},
		Size: 2048, Yes: true,
	})
	manager.out = &bytes.Buffer{}
	lookups := 0
	manager.lookupTXT = func(name string) ([]string, error) {
		lookups++
		for _, credential := range current.Credentials() {
			if strings.HasPrefix(name, credential.Selector()+".") {
				return []string{dnsRecord(credential)}, nil
			}
		}
		return nil, errors.New("not found")
	}
	if _, err := manager.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if lookups != 2 {
		t.Fatalf("DNS lookups = %d, want both profile credentials", lookups)
	}
	if repository.publishes != 1 || repository.expected != 1 {
		t.Fatalf("publication = count %d expected %d", repository.publishes, repository.expected)
	}
	profiles := repository.published.Profiles()
	policies := repository.published.Policies()
	if profiles[0].Status() != dkim2model.RecordStatusActive ||
		policies[0].Status() != dkim2model.RecordStatusActive ||
		policies[0].Rollout() != dkim2model.RolloutEnforce {
		t.Fatalf("activation state was not published")
	}
}

func TestDKIM2ActivationRejectsAmbiguousDNSWithoutWrite(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	manager := testDKIM2Manager(repository, &cli.Options{
		Active: true, Domains: []string{"example.test"}, Selectors: []string{"selector-rsa"},
		Size: 2048, Yes: true,
	})
	manager.lookupTXT = func(string) ([]string, error) { return []string{"one", "two"}, nil }
	if _, err := manager.Run(); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("Run() error = %v", err)
	}
	if repository.publishes != 0 {
		t.Fatalf("publishes = %d", repository.publishes)
	}
}

func TestDKIM2ActivationRejectsWrongAlgorithmAndRevocationWithoutWrite(t *testing.T) {
	for _, record := range []string{
		"v=DKIM1; k=ed25519; h=sha256; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"v=DKIM1; k=rsa; h=sha256; p=",
	} {
		current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
		repository := &fakeGenerationRepository{current: current}
		manager := testDKIM2Manager(repository, &cli.Options{
			Active: true, Domains: []string{"example.test"}, Selectors: []string{"selector-rsa"},
			Size: 2048, Yes: true,
		})
		manager.lookupTXT = func(string) ([]string, error) { return []string{record}, nil }
		if _, err := manager.Run(); err == nil {
			t.Fatalf("Run() accepted unsafe DNS record %q", record)
		}
		if repository.publishes != 0 {
			t.Fatalf("publishes = %d for %q", repository.publishes, record)
		}
		repository.close()
	}
}

func TestDKIM2DNSProofUsesAbsoluteQueryName(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	manager := testDKIM2Manager(repository, &cli.Options{
		TestKey: true, Selectors: []string{"selector-ed"},
	})
	manager.lookupTXT = func(name string) ([]string, error) {
		if name != "selector-ed._domainkey.example.test." {
			t.Fatalf("DNS proof query = %q, want absolute FQDN", name)
		}
		credential, found := current.CredentialByDomainSelector("example.test", "selector-ed")
		if !found {
			t.Fatal("test credential unavailable")
		}
		return []string{dnsRecord(credential)}, nil
	}
	if _, err := manager.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestDKIM2RSADNSUsesSPKIAndAcceptsEquivalentPKCS1Proof(t *testing.T) {
	pair, err := dkim2model.GenerateRSAKeyPair(dkim2model.DefaultRSABits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	spki := pair.PublicSPKIDER()
	credential, err := dkim2model.NewCredential(
		1, "profile-test", "selector-rsa", dkim2model.AlgorithmRSASHA256, spki, "handle-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, published, err := parseDNSRecord(dnsRecord(credential))
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != dkim2model.AlgorithmRSASHA256 || !bytes.Equal(published, spki) {
		t.Fatal("DKIM2 RSA DNS record does not preserve the canonical SPKI payload")
	}
	privateDER := pair.PrivatePKCS8DER()
	defer clear(privateDER)
	classic := dkim.NewKeys()
	if err := classic.GeneratePublicRSA(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))); err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(published) != classic.RSAPublicKey() {
		t.Fatal("DKIM2 and OpenDKIM modes produce different RSA DNS payloads")
	}
	publicAny, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := publicAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T", publicAny)
	}
	pkcs1Record := "v=DKIM1; k=rsa; h=sha256; p=" +
		base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(public))
	manager := &DKIM2Manager{lookupTXT: func(string) ([]string, error) {
		return []string{pkcs1Record}, nil
	}}
	if err := manager.verifyCredential(credential, "example.test"); err != nil {
		t.Fatalf("DKIM2 DNS proof rejected the equivalent PKCS#1 RSA payload: %v", err)
	}
	otherPair, err := dkim2model.GenerateRSAKeyPair(dkim2model.DefaultRSABits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = otherPair.Close() }()
	otherPublicAny, err := x509.ParsePKIXPublicKey(otherPair.PublicSPKIDER())
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, ok := otherPublicAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("other public key type = %T", otherPublicAny)
	}
	manager.lookupTXT = func(string) ([]string, error) {
		return []string{"v=DKIM1; k=rsa; h=sha256; p=" +
			base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(otherPublic))}, nil
	}
	if err := manager.verifyCredential(credential, "example.test"); err == nil {
		t.Fatal("DKIM2 DNS proof accepted PKCS#1 material for a different RSA key")
	}
}

func TestDKIM2ListAndPrintDNSNeverExposeHandlesOrPrivateMaterial(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	for _, opts := range []*cli.Options{{List: true}, {PrintDNS: true}} {
		manager := testDKIM2Manager(repository, opts)
		var output bytes.Buffer
		manager.out = &output
		if _, err := manager.Run(); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if strings.Contains(output.String(), "handle-secret-marker") || strings.Contains(output.String(), "PRIVATE") {
			t.Fatalf("protected identifier or private marker leaked: %q", output.String())
		}
	}
}

func TestDKIM2PrintDNSRejectsAnEmptyExactSelection(t *testing.T) {
	current := testGeneration(t, dkim2model.RecordStatusDisabled, dkim2model.RolloutOff)
	repository := &fakeGenerationRepository{current: current}
	defer repository.close()
	manager := testDKIM2Manager(repository, &cli.Options{
		PrintDNS: true, Domains: []string{"missing.example.test"},
	})
	if _, err := manager.Run(); err == nil {
		t.Fatal("Run() reported successful DNS output for an empty exact selection")
	}
}

func TestParseDKIM2DNSRecordRejectsUnknownAndNoncanonicalFields(t *testing.T) {
	for _, record := range []string{
		"v=DKIM1; k=rsa; h=sha256; p=YQ==; x=unexpected",
		"v=DKIM1; k=rsa; k=ed25519; h=sha256; p=YQ==",
		"k=rsa; v=DKIM1; p=YQ==",
		"v=DKIM1; k=rsa; p=",
		"v=DKIM1; k=rsa; p=Y===",
		"v=DKIM1; k=rsa; p=YQ==; t=y::s",
	} {
		if _, _, err := parseDNSRecord(record); err == nil {
			t.Fatalf("parseDNSRecord(%q) unexpectedly succeeded", record)
		}
	}
}

func TestParseDKIM2DNSRecordAcceptsDNS04OptionalFieldsAndPadding(t *testing.T) {
	for _, record := range []string{
		"p=YQ; h=retired; n=; s=; t=y:future",
		"v=DKIM1; k=rsa; h=sha1; p=YQ==;",
	} {
		algorithm, public, err := parseDNSRecord(record)
		if err != nil {
			t.Fatalf("parseDNSRecord(%q) error = %v", record, err)
		}
		if algorithm != dkim2model.AlgorithmRSASHA256 || string(public) != "a" {
			t.Fatalf("parseDNSRecord(%q) = %q %x", record, algorithm, public)
		}
	}
}

func testDKIM2Manager(repository *fakeGenerationRepository, opts *cli.Options) *DKIM2Manager {
	cfg := &config.Config{
		Global: config.GlobalConfig{Mode: types.ModeDKIM2, KeyType: "both"},
		DKIM2: config.DKIM2Config{
			TenantID: "tenant-test", ProfileUse: "originator", Rollout: "enforce",
			Compatibility: "strict",
		},
		KeyType: types.DKIMKeyTypeBoth,
	}
	return &DKIM2Manager{
		cfg: cfg, opts: opts, repository: repository, random: rand.Reader,
		in: strings.NewReader("yes\n"), out: &bytes.Buffer{},
	}
}

func testGeneration(t *testing.T, status dkim2model.RecordStatus, rollout dkim2model.Rollout) *dkim2model.Generation {
	t.Helper()
	builder, err := dkim2model.NewBuilder(1, dkim2model.DatasetStateCommitted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = builder.Close() }()
	profile, err := dkim2model.NewProfile(1, "profile-test", "example.test", status, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var credentials []dkim2model.Credential
	var materials []*dkim2model.KeyMaterial
	for index, algorithm := range []dkim2model.Algorithm{
		dkim2model.AlgorithmRSASHA256, dkim2model.AlgorithmEd25519SHA256,
	} {
		pair, pairErr := dkim2model.GenerateKeyPair(algorithm, 2048, nil)
		if pairErr != nil {
			t.Fatal(pairErr)
		}
		selectorName := []string{"selector-rsa", "selector-ed"}[index]
		handleID := []string{"handle-secret-marker-rsa", "handle-secret-marker-ed"}[index]
		credential, credentialErr := dkim2model.NewCredential(1, profile.ID(), selectorName, algorithm, pair.PublicSPKIDER(), handleID)
		material, materialErr := dkim2model.NewKeyMaterial(1, "tenant-test", "example.test", dkim2model.ProfileUseOriginator, handleID, pair)
		_ = pair.Close()
		if credentialErr != nil || materialErr != nil {
			t.Fatal(errors.Join(credentialErr, materialErr))
		}
		credentials = append(credentials, credential)
		materials = append(materials, material)
	}
	defer closeMaterials(materials)
	policy, err := dkim2model.NewPolicy(
		1, "tenant-test", "example.test", dkim2model.ProfileUseOriginator, profile.ID(),
		status, rollout, dkim2model.CompatibilityStrict, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.AddProfileWithKeys(profile, credentials, policy, materials); err != nil {
		t.Fatal(err)
	}
	generation, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return generation
}
