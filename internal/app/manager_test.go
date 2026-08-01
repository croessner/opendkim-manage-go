package app

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

func TestRevokedRetentionIsTimeBased(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if shouldDeleteRevoked(now.AddDate(0, 0, -29), 99, 30, 1, now) {
		t.Fatal("record was deleted before its retention period")
	}
	if !shouldDeleteRevoked(now.AddDate(0, 0, -30), 0, 30, 99, now) {
		t.Fatal("record was not deleted when its retention period elapsed")
	}
}

func TestRevokedLegacyCountModeHasNoOffByOne(t *testing.T) {
	now := time.Now().UTC()
	if shouldDeleteRevoked(now, 5, 0, 6, now) {
		t.Fatal("sixth retained record must remain")
	}
	if !shouldDeleteRevoked(now, 6, 0, 6, now) {
		t.Fatal("seventh record must be deleted")
	}
}

func TestCNAMEEncodingRejectsUnderscoreCollision(t *testing.T) {
	if err := validateLDHDomain("customer_name.example"); err == nil {
		t.Fatal("expected underscore-containing source domain to be rejected")
	}
	if err := validateLDHDomain("customer-name.example"); err != nil {
		t.Fatalf("valid LDH domain rejected: %v", err)
	}
}

func TestCNAMETargetHonorsConfiguredAllowlist(t *testing.T) {
	m := &Manager{cfg: &config.Config{DNS: config.DNSConfig{CNAMEs: "cnames.example.com"}}}
	domain := &ldapstore.Domain{DomainName: "customer.example", DestinationIndicator: "other.example"}
	if _, _, err := m.cnameTarget(domain); err == nil {
		t.Fatal("expected non-allowlisted destination to be rejected")
	}
	domain.DestinationIndicator = "cnames.example.com"
	zone, subdomain, err := m.cnameTarget(domain)
	if err != nil {
		t.Fatalf("allowlisted destination rejected: %v", err)
	}
	if zone != "cnames.example.com" || subdomain != "customer_example" {
		t.Fatalf("unexpected target: zone=%q subdomain=%q", zone, subdomain)
	}
}

func TestCNAMETargetRejectsEmptyAllowlist(t *testing.T) {
	m := &Manager{cfg: &config.Config{}}
	domain := &ldapstore.Domain{DomainName: "customer.example", DestinationIndicator: "cnames.example"}
	if _, _, err := m.cnameTarget(domain); err == nil {
		t.Fatal("expected empty CNAME allowlist to reject destinationIndicator")
	}
}

func TestMutationPreflightRejectsCNAMEBeforeWrites(t *testing.T) {
	m := &Manager{cfg: &config.Config{DNS: config.DNSConfig{CNAMEs: "allowed.example"}}}
	domain := &ldapstore.Domain{
		DomainName:           "customer.example",
		DestinationIndicator: "not-allowed.example",
		ServiceType:          "email",
	}
	if err := m.validateDomainForMutation(domain.DomainName, domain); err == nil {
		t.Fatal("expected mutation preflight to reject non-allowlisted destinationIndicator")
	}
}

func TestAutoPreflightRequiresDNSUpdatesForCNAME(t *testing.T) {
	m := &Manager{
		opts: &cli.Options{},
		cfg:  &config.Config{DNS: config.DNSConfig{CNAMEs: "allowed.example"}},
	}
	domain := &ldapstore.Domain{
		DomainName:           "customer.example",
		DestinationIndicator: "allowed.example",
		ServiceType:          "email",
	}
	if err := m.validateAutoDomainForMutation(domain.DomainName, domain); err == nil {
		t.Fatal("expected live CNAME auto run without DNS updates to fail before mutations")
	}
	m.opts.DryRun = true
	if err := m.validateAutoDomainForMutation(domain.DomainName, domain); err != nil {
		t.Fatalf("dry-run must be able to simulate CNAME reconciliation: %v", err)
	}
}

func TestValidateServiceType(t *testing.T) {
	for _, value := range []string{"", "*", "email", "email:other-service"} {
		if err := validateServiceType(value); err != nil {
			t.Fatalf("valid service type %q rejected: %v", value, err)
		}
	}
	if err := validateServiceType("email; p=attacker"); err == nil {
		t.Fatal("expected invalid service type to be rejected")
	}
}

func TestDKIMTXTContentHasCanonicalSeparators(t *testing.T) {
	content, err := dkimTXTContent(types.DKIMKeyTypeRSA, "email", "PUBLIC")
	if err != nil {
		t.Fatalf("build content: %v", err)
	}
	if content != "v=DKIM1; k=rsa; h=sha256; s=email; p=PUBLIC" {
		t.Fatalf("unexpected content: %q", content)
	}
}

func TestParseDKIMTXTRecordsRejectsMultipleRecords(t *testing.T) {
	if _, _, err := parseDKIMTXTRecords([]string{"v=DKIM1; p=one", "v=DKIM1; p=two"}); err == nil {
		t.Fatal("expected multiple TXT RRs to be rejected")
	}
}

func TestPlanCNAMERenamesOrdersDependencyChain(t *testing.T) {
	newest := &ldapstore.Selector{SelectorName: "new-key", LDAPDN: "DKIMSelector=new-key,dc=example"}
	current := &ldapstore.Selector{SelectorName: "rsa-1", LDAPDN: "DKIMSelector=rsa-1,dc=example", State: types.DKIMEnabled}
	previous := &ldapstore.Selector{SelectorName: "rsa-2", LDAPDN: "DKIMSelector=rsa-2,dc=example"}
	plans := []cnameSlotPlan{
		{source: "new-key", target: "rsa-1", selector: newest},
		{source: "rsa-1", target: "rsa-2", selector: current},
		{source: "rsa-2", target: "rsa-3", selector: previous},
	}
	steps, err := planCNAMERenames(plans, map[string]*ldapstore.Selector{"new-key": newest, "rsa-1": current, "rsa-2": previous})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	want := []cnameRenameStep{{from: "rsa-2", to: "rsa-3"}, {from: "rsa-1", to: "rsa-2"}, {from: "new-key", to: "rsa-1"}}
	if len(steps) != len(want) {
		t.Fatalf("unexpected steps: %#v", steps)
	}
	for index := range want {
		if steps[index] != want[index] {
			t.Fatalf("step %d: got %#v want %#v", index, steps[index], want[index])
		}
	}
}

func TestPlanCNAMERenamesUsesTemporaryNameOnlyForInactiveCycleMember(t *testing.T) {
	active := &ldapstore.Selector{SelectorName: "rsa-2", LDAPDN: "DKIMSelector=rsa-2,dc=example", State: types.DKIMEnabled}
	inactive := &ldapstore.Selector{SelectorName: "rsa-1", LDAPDN: "DKIMSelector=rsa-1,dc=example"}
	plans := []cnameSlotPlan{{source: "rsa-2", target: "rsa-1", selector: active}, {source: "rsa-1", target: "rsa-2", selector: inactive}}
	steps, err := planCNAMERenames(plans, map[string]*ldapstore.Selector{"rsa-1": inactive, "rsa-2": active})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if len(steps) != 3 || steps[0].from != "rsa-1" || !strings.HasPrefix(steps[0].to, "dkimtmp-") {
		t.Fatalf("unexpected cycle break: %#v", steps)
	}
	for _, step := range steps {
		if step.from == "rsa-2" && strings.HasPrefix(step.to, "dkimtmp-") {
			t.Fatal("active selector was assigned a temporary name")
		}
	}
}

func TestDryRunWriteWrappersDoNotNeedExternalClients(t *testing.T) {
	m := &Manager{opts: &cli.Options{DryRun: true}}
	if err := m.storeDKIMKey("dn", "PRIVATE", types.DKIMKeyTypeRSA, "example.org", "example.org", nil); err != nil {
		t.Fatalf("dry-run LDAP add: %v", err)
	}
	if err := m.renameSelectorDN("dn", "new"); err != nil {
		t.Fatalf("dry-run LDAP rename: %v", err)
	}
	if err := m.setActive("dn", true); err != nil {
		t.Fatalf("dry-run LDAP activation: %v", err)
	}
	if err := m.changeDNSDKIMKey("example.org", "selector", "content", ""); err != nil {
		t.Fatalf("dry-run DNS change: %v", err)
	}
}

func TestReconcileActiveSigningDomainPlansExactToWildcardInDryRun(t *testing.T) {
	const domainName = "tenant.example.org"
	selector := &ldapstore.Selector{
		DomainName:    domainName,
		SelectorName:  "rsa-2026",
		LDAPDN:        "DKIMSelector=rsa-2026,associatedDomain=tenant.example.org,dc=example,dc=org",
		State:         types.DKIMEnabled,
		KeyType:       types.DKIMKeyTypeRSA,
		SigningDomain: domainName,
	}
	domain := &ldapstore.Domain{
		DomainName: domainName,
		Selectors:  map[string]*ldapstore.Selector{selector.SelectorName: selector},
	}
	writes := 0
	m := &Manager{
		opts: &cli.Options{DryRun: true},
		runtime: RuntimeConfig{MultipleSignaturesDomains: map[string]struct{}{
			domainName: {},
		}},
		replaceDKIMDomain: func(_, _ string) error {
			writes++
			return nil
		},
	}

	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("open stderr pipe: %v", err)
	}
	originalStderr := os.Stderr
	os.Stderr = stderrWriter
	reconcileErr := m.reconcileActiveSigningDomains(domain)
	closeWriterErr := stderrWriter.Close()
	os.Stderr = originalStderr
	if closeWriterErr != nil {
		t.Fatalf("close stderr writer: %v", closeWriterErr)
	}
	output, readErr := io.ReadAll(stderrReader)
	if closeErr := stderrReader.Close(); closeErr != nil {
		t.Fatalf("close stderr reader: %v", closeErr)
	}
	if readErr != nil {
		t.Fatalf("read dry-run output: %v", readErr)
	}
	if reconcileErr != nil {
		t.Fatalf("reconcile active signing domains: %v", reconcileErr)
	}
	if !strings.Contains(string(output), "would replace LDAP DKIMDomain") || !strings.Contains(string(output), "current=tenant.example.org expected=*") {
		t.Fatalf("dry-run did not report the planned DKIMDomain correction: %q", output)
	}
	if writes != 0 {
		t.Fatalf("dry-run performed %d LDAP writes", writes)
	}
	if selector.SigningDomain != "*" {
		t.Fatalf("dry-run did not simulate wildcard correction: %q", selector.SigningDomain)
	}
}

func TestReconcileActiveSigningDomainReplacesWildcardWithExactOnly(t *testing.T) {
	const domainName = "single.example.org"
	created := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	modified := time.Date(2026, 7, 2, 11, 0, 0, 0, time.UTC)
	selector := &ldapstore.Selector{
		DomainName:    domainName,
		SelectorName:  "ed25519-2026",
		LDAPDN:        "DKIMSelector=ed25519-2026,associatedDomain=single.example.org,dc=example,dc=org",
		SigningDomain: "*",
		Created:       created,
		Modified:      modified,
		State:         types.DKIMEnabled,
		RevokeState:   types.RevokeDisabled,
		KeyType:       types.DKIMKeyTypeED25519,
		Key:           "opaque-test-key",
	}
	domain := &ldapstore.Domain{
		DomainName: domainName,
		Selectors:  map[string]*ldapstore.Selector{selector.SelectorName: selector},
	}
	type replacement struct {
		dn    string
		value string
	}
	replacements := make([]replacement, 0, 1)
	m := &Manager{
		opts: &cli.Options{},
		replaceDKIMDomain: func(dn, value string) error {
			replacements = append(replacements, replacement{dn: dn, value: value})
			return nil
		},
	}

	if err := m.reconcileActiveSigningDomains(domain); err != nil {
		t.Fatalf("reconcile active signing domains: %v", err)
	}
	if len(replacements) != 1 || replacements[0].dn != selector.LDAPDN || replacements[0].value != domainName {
		t.Fatalf("unexpected LDAP replacement: %#v", replacements)
	}
	if selector.SigningDomain != domainName {
		t.Fatalf("selector did not converge to the exact signing domain: %q", selector.SigningDomain)
	}
	if selector.DomainName != domainName || selector.SelectorName != "ed25519-2026" || selector.KeyType != types.DKIMKeyTypeED25519 || selector.Key != "opaque-test-key" || selector.State != types.DKIMEnabled || selector.RevokeState != types.RevokeDisabled || !selector.Created.Equal(created) || !selector.Modified.Equal(modified) {
		t.Fatal("reconciliation changed selector state outside DKIMDomain")
	}
	if err := m.reconcileActiveSigningDomains(domain); err != nil {
		t.Fatalf("repeat reconciliation: %v", err)
	}
	if len(replacements) != 1 {
		t.Fatalf("idempotent reconciliation performed %d replacements", len(replacements))
	}
}

func TestReconcileSigningDomainLeavesInactiveHistoryUntouched(t *testing.T) {
	const domainName = "history.example.org"
	selector := &ldapstore.Selector{
		DomainName:    domainName,
		SelectorName:  "old-rsa",
		LDAPDN:        "DKIMSelector=old-rsa,associatedDomain=history.example.org,dc=example,dc=org",
		SigningDomain: domainName,
		State:         types.DKIMDisabled,
		KeyType:       types.DKIMKeyTypeRSA,
	}
	domain := &ldapstore.Domain{DomainName: domainName, Selectors: map[string]*ldapstore.Selector{selector.SelectorName: selector}}
	writes := 0
	m := &Manager{
		opts: &cli.Options{},
		runtime: RuntimeConfig{MultipleSignaturesDomains: map[string]struct{}{
			domainName: {},
		}},
		replaceDKIMDomain: func(_, _ string) error {
			writes++
			return nil
		},
	}

	if err := m.reconcileActiveSigningDomains(domain); err != nil {
		t.Fatalf("reconcile inactive history: %v", err)
	}
	if writes != 0 || selector.SigningDomain != domainName {
		t.Fatal("inactive selector history was rewritten")
	}
}

func TestReconcileSigningDomainFailsClosedOnLDAPError(t *testing.T) {
	const domainName = "failure.example.org"
	selector := &ldapstore.Selector{
		DomainName:    domainName,
		SelectorName:  "rsa-current",
		LDAPDN:        "DKIMSelector=rsa-current,associatedDomain=failure.example.org,dc=example,dc=org",
		SigningDomain: domainName,
		State:         types.DKIMEnabled,
		KeyType:       types.DKIMKeyTypeRSA,
	}
	domain := &ldapstore.Domain{DomainName: domainName, Selectors: map[string]*ldapstore.Selector{selector.SelectorName: selector}}
	m := &Manager{
		opts: &cli.Options{},
		runtime: RuntimeConfig{MultipleSignaturesDomains: map[string]struct{}{
			domainName: {},
		}},
		replaceDKIMDomain: func(_, _ string) error {
			return errors.New("ldap replace DKIMDomain request failed")
		},
	}

	if err := m.reconcileActiveSigningDomains(domain); err == nil {
		t.Fatal("expected LDAP replacement failure")
	}
	if selector.SigningDomain != domainName {
		t.Fatal("failed LDAP replacement was applied to the in-memory selector")
	}
}

func TestNewManagerPreservesConfiguredMaxRevokedWhenFlagUnset(t *testing.T) {
	cfg := &config.Config{
		Global:  config.GlobalConfig{MaxRevoked: 17},
		LDAP:    config.LDAPConfig{URI: "ldaps://ldap.example/ou=dkim"},
		Scheme:  types.DefaultScheme(),
		KeyType: types.DKIMKeyTypeRSA,
	}
	m, err := NewManager(cfg, &cli.Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})
	if m.runtime.MaxRevoked != 17 {
		t.Fatalf("configured max_revoked was overwritten: %d", m.runtime.MaxRevoked)
	}
}
