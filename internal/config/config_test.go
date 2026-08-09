package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/types"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	path := writeTemp(t, `
global:
  selectorformat: "s${randomhex:8}.${year}-${month}"
  keytype: both
ldap:
  uri: "ldap://localhost:389/ou=dkim,o=company??sub?(&(objectClass=domain)(associatedDomain={0}))"
  domain: associatedDomain
  use_starttls: true
dns:
  primary_nameserver: "127.0.0.1"
  ttl: 3600
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	if cfg.KeyType.String() != "both" {
		t.Fatalf("unexpected key type: %s", cfg.KeyType.String())
	}
}

func TestValidateRejectsImplicitPlaintextLDAP(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldap://ldap.example.org/ou=dkim,dc=example"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected plaintext LDAP to be rejected")
	}
}

func TestValidateAllowsExplicitLegacyPlaintextException(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldap://ldap.example.org/ou=dkim,dc=example"
	cfg.LDAP.AllowInsecure = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit legacy exception rejected: %v", err)
	}
}

func TestValidateRejectsUnimplementedSASLMechanism(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	cfg.LDAP.BindMethod = "sasl"
	cfg.LDAP.SASLMech = "digest-md5"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsupported SASL mechanism to be rejected")
	}
}

func TestValidateRequiresClientCertificateForSASLExternal(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	cfg.LDAP.BindMethod = "sasl"
	cfg.LDAP.SASLMech = "external"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected SASL EXTERNAL without client certificate to fail")
	}
	cfg.LDAP.Cert = "/etc/ldap/client.crt"
	cfg.LDAP.Key = "/etc/ldap/client.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid SASL EXTERNAL config rejected: %v", err)
	}
}

func TestValidateRejectsSASLMechanismWithoutSASLBindMethod(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	cfg.LDAP.SASLMech = "external"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected ignored SASL mechanism to be rejected")
	}
}

func TestValidateRequiresCompleteTSIGPair(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	cfg.DNS.TSIGKeyName = "update-key"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected incomplete TSIG configuration to fail")
	}
}

func TestValidateRejectsIgnoredLDAPOptions(t *testing.T) {
	for _, field := range []string{"ciphers", "authz_id"} {
		cfg := defaultConfig()
		cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
		if field == "ciphers" {
			cfg.LDAP.Ciphers = "HIGH"
		} else {
			cfg.LDAP.AuthzID = "dn:cn=dkim"
		}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected %s to be rejected while unimplemented", field)
		}
	}
}

func TestLoadUnknownFieldFails(t *testing.T) {
	path := writeTemp(t, `
global:
  selectorformat: "foo"
  keytype: both
  unknown_field: x
ldap:
  uri: "ldap://localhost:389/ou=dkim,o=company"
  domain: associatedDomain
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict schema error")
	}
}

func TestLoadDefaultsToOpenDKIMMode(t *testing.T) {
	path := writeTemp(t, `
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Global.Mode != types.ModeOpenDKIM {
		t.Fatalf("mode = %q, want %q", cfg.Global.Mode, types.ModeOpenDKIM)
	}
}

func TestLoadDKIM2ModeAndTypedConfiguration(t *testing.T) {
	path := writeTemp(t, `
global:
  mode: dkim2
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
dkim2:
  tenant_id: tenant-example
  profile_use: ordinary_transit
  rollout: observe
  compatibility: strict
  feedback_route_id: feedback-primary
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Global.Mode != types.ModeDKIM2 {
		t.Fatalf("mode = %q, want %q", cfg.Global.Mode, types.ModeDKIM2)
	}
	if cfg.DKIM2.ProfileUse != "ordinary_transit" || cfg.DKIM2.FeedbackRouteID != "feedback-primary" {
		t.Fatalf("unexpected DKIM2 config: %#v", cfg.DKIM2)
	}
}

func TestLoadDKIM2DeliveryStatusNativeKeyConfiguration(t *testing.T) {
	path := writeTemp(t, `
global:
  mode: dkim2
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
dkim2:
  tenant_id: tenant-example
  profile_use: delivery_status
  rollout: enforce
  compatibility: strict
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load delivery-status config: %v", err)
	}
	if cfg.DKIM2.ProfileUse != "delivery_status" {
		t.Fatalf("profile use = %q, want delivery_status", cfg.DKIM2.ProfileUse)
	}
}

func TestValidateRejectsUnknownAndEmptyExplicitModes(t *testing.T) {
	for _, mode := range []types.Mode{"", "DKIM2", " dkim2", "future"} {
		cfg := defaultConfig()
		cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
		cfg.Global.Mode = mode
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected mode %q to be rejected", mode)
		}
	}
}

func TestLoadRejectsExplicitEmptyModes(t *testing.T) {
	for _, value := range []string{`""`, `null`} {
		t.Run(value, func(t *testing.T) {
			path := writeTemp(t, `
global:
  mode: `+value+`
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
`)
			if _, err := Load(path); err == nil {
				t.Fatalf("expected explicit mode %s to be rejected", value)
			}
		})
	}
}

func TestValidateDKIM2RequiresClosedConfiguration(t *testing.T) {
	valid := defaultConfig()
	valid.Global.Mode = types.ModeDKIM2
	valid.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	valid.DKIM2.TenantID = "tenant-example"
	valid.DKIM2.ProfileUse = "originator"
	valid.DKIM2.Rollout = "enforce"
	valid.DKIM2.Compatibility = "strict"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid DKIM2 config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DKIM2Config)
	}{
		{name: "tenant missing", mutate: func(c *DKIM2Config) { c.TenantID = "" }},
		{name: "tenant uppercase", mutate: func(c *DKIM2Config) { c.TenantID = "Tenant" }},
		{name: "tenant leading punctuation", mutate: func(c *DKIM2Config) { c.TenantID = "-tenant" }},
		{name: "tenant oversized", mutate: func(c *DKIM2Config) { c.TenantID = strings.Repeat("a", 129) }},
		{name: "profile use", mutate: func(c *DKIM2Config) { c.ProfileUse = "transit" }},
		{name: "unsupported native key use", mutate: func(c *DKIM2Config) { c.ProfileUse = "next_domain_transit" }},
		{name: "rollout", mutate: func(c *DKIM2Config) { c.Rollout = "enabled" }},
		{name: "compatibility", mutate: func(c *DKIM2Config) { c.Compatibility = "legacy" }},
		{name: "feedback route", mutate: func(c *DKIM2Config) { c.FeedbackRouteID = "bad route" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			cfg.DKIM2 = valid.DKIM2
			tt.mutate(&cfg.DKIM2)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected invalid DKIM2 config to be rejected")
			}
		})
	}
}

func TestValidateForModeChecksCLIOverrideRequirements(t *testing.T) {
	cfg := defaultConfig()
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
	if err := cfg.ValidateForMode(types.ModeDKIM2); err == nil {
		t.Fatal("expected DKIM2 override without DKIM2 config to fail")
	}
}

func TestLoadDKIM2RotationDefaults(t *testing.T) {
	path := writeTemp(t, `
global:
  mode: dkim2
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
dkim2:
  tenant_id: tenant-example
  profile_use: originator
  rollout: enforce
  compatibility: strict
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load DKIM2 defaults: %v", err)
	}
	if cfg.DKIM2.RotationEnabled || cfg.DKIM2.RotateAfterDays != 30 || cfg.DKIM2.HistoryLimit != 16384 ||
		cfg.DKIM2.MaxCampaignBindings != 16384 ||
		cfg.DKIM2.MaxGenerationEntries != 131072 || cfg.DKIM2.MaxAttributeBytes != 64<<10 ||
		cfg.DKIM2.MaxDatasetBytes != 1<<30 || cfg.DKIM2.MaxLDAPRequests != 262144 ||
		cfg.DKIM2.MaxLDAPBytes != 1<<30 || cfg.DKIM2.MaxRetainedRootVisits != 32768 ||
		cfg.DKIM2.IdentifierAllocationAttempts != 32 || cfg.DKIM2.PublicationReadbackAttempts != 8 ||
		cfg.DKIM2.PublicationReadbackIntervalMillis != 25 ||
		cfg.DKIM2.LDAPSearchTimeLimitSeconds != 30 ||
		cfg.DKIM2.LDAPOperationTimeoutSeconds != 60 || cfg.DKIM2.AuthorityPasswordMaxBytes != 16384 ||
		cfg.DKIM2.MaxClockSkewSeconds != 300 || cfg.DKIM2.RunTimeoutSeconds != 86400 ||
		cfg.DKIM2.ProofPollIntervalSeconds != 5 || cfg.DKIM2.ProofMaxAttempts != 3600 ||
		cfg.DKIM2.DNSQueryTimeoutSeconds != 5 || cfg.DKIM2.RetirementMinOverlapSeconds != 604800 ||
		!cfg.DKIM2.Retention.Enabled || cfg.DKIM2.Retention.MaxGenerations != 12 ||
		cfg.DKIM2.Retention.MinRollbackGenerations != 2 || cfg.DKIM2.Retention.MaxDeleteBatch != 64 ||
		cfg.DKIM2.Retention.JournalFile != "/var/lib/opendkim-manage-go/dkim2-retention-plan.json" ||
		cfg.DKIM2.Retention.MaxJournalBytes != 4096 {
		t.Fatalf("unexpected DKIM2 rotation defaults: %#v", cfg.DKIM2)
	}
	if cfg.DNS.PrimaryNameserver != "127.0.0.1:53" || cfg.DNS.RecursiveNameserver != "127.0.0.2:53" {
		t.Fatalf("unexpected proof endpoints: %#v", cfg.DNS)
	}
}

func TestLoadDKIM2OperationalLimitsAreFullyOverrideable(t *testing.T) {
	path := writeTemp(t, `
global:
  mode: dkim2
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
dkim2:
  tenant_id: tenant-example
  profile_use: originator
  rollout: enforce
  compatibility: strict
  rotate_after_days: 31
  history_limit: 256
  max_campaign_bindings: 128
  max_generation_entries: 8192
  max_attribute_bytes: 32768
  max_dataset_bytes: 16777216
  max_ldap_requests: 4096
  max_ldap_bytes: 33554432
  max_retained_root_visits: 512
  identifier_allocation_attempts: 24
  publication_readback_attempts: 6
  publication_readback_interval_millis: 40
  ldap_search_time_limit_seconds: 12
  ldap_operation_timeout_seconds: 45
  authority_password_max_bytes: 8192
  authority_password_preserve_trailing_newline: true
  max_clock_skew_seconds: 120
  run_timeout_seconds: 7200
  proof_poll_interval_seconds: 3
  proof_max_attempts: 240
  dns_query_timeout_seconds: 4
  retirement_min_overlap_seconds: 86400
  retention:
    enabled: true
    max_generations: 24
    min_rollback_generations: 3
    max_delete_batch: 16
    journal_file: /var/lib/opendkim-manage-go/custom-retention-plan.json
    max_journal_bytes: 8192
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load overridden DKIM2 limits: %v", err)
	}
	if cfg.DKIM2.RotateAfterDays != 31 || cfg.DKIM2.HistoryLimit != 256 || cfg.DKIM2.MaxCampaignBindings != 128 ||
		cfg.DKIM2.MaxGenerationEntries != 8192 || cfg.DKIM2.MaxAttributeBytes != 32768 ||
		cfg.DKIM2.MaxDatasetBytes != 16777216 || cfg.DKIM2.MaxLDAPRequests != 4096 ||
		cfg.DKIM2.MaxLDAPBytes != 33554432 || cfg.DKIM2.MaxRetainedRootVisits != 512 ||
		cfg.DKIM2.IdentifierAllocationAttempts != 24 || cfg.DKIM2.PublicationReadbackAttempts != 6 ||
		cfg.DKIM2.PublicationReadbackIntervalMillis != 40 ||
		cfg.DKIM2.LDAPSearchTimeLimitSeconds != 12 ||
		cfg.DKIM2.LDAPOperationTimeoutSeconds != 45 || cfg.DKIM2.AuthorityPasswordMaxBytes != 8192 ||
		!cfg.DKIM2.AuthorityPasswordPreserveNewline ||
		cfg.DKIM2.Retention.MaxGenerations != 24 || cfg.DKIM2.Retention.MinRollbackGenerations != 3 ||
		cfg.DKIM2.Retention.MaxDeleteBatch != 16 ||
		cfg.DKIM2.Retention.JournalFile != "/var/lib/opendkim-manage-go/custom-retention-plan.json" ||
		cfg.DKIM2.Retention.MaxJournalBytes != 8192 {
		t.Fatalf("operational override was not preserved: %#v", cfg.DKIM2)
	}
}

func TestValidateDKIM2AutomaticAuthoritiesAreCompleteAndDistinct(t *testing.T) {
	cfg := defaultConfig()
	cfg.Global.Mode = types.ModeDKIM2
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim2,o=company"
	cfg.LDAP.BindMethod = "simple"
	cfg.DKIM2.TenantID = "tenant-example"
	cfg.DKIM2.ProfileUse = "originator"
	cfg.DKIM2.Rollout = "enforce"
	cfg.DKIM2.Compatibility = "strict"
	cfg.DKIM2.RotationEnabled = true
	cfg.DKIM2.LDAPAuthorities = DKIM2LDAPAuthorities{
		Snapshot:   DKIM2LDAPAuthority{BindDN: "cn=snapshot,o=company", PasswordFile: "/run/secrets/snapshot"},
		Staging:    DKIM2LDAPAuthority{BindDN: "cn=staging,o=company", PasswordFile: "/run/secrets/staging"},
		Activation: DKIM2LDAPAuthority{BindDN: "cn=activation,o=company", PasswordFile: "/run/secrets/activation"},
		Purge:      DKIM2LDAPAuthority{BindDN: "cn=purge,o=company", PasswordFile: "/run/secrets/purge"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid automatic authorities rejected: %v", err)
	}

	duplicate := cfg
	duplicate.DKIM2.LDAPAuthorities.Purge.PasswordFile = duplicate.DKIM2.LDAPAuthorities.Staging.PasswordFile
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate automatic authority password files were accepted")
	}
	missing := cfg
	missing.DKIM2.LDAPAuthorities.Activation = DKIM2LDAPAuthority{}
	if err := missing.Validate(); err == nil {
		t.Fatal("missing automatic activation authority was accepted")
	}
	nonCanonical := cfg
	nonCanonical.DKIM2.Retention.JournalFile = "/var/lib/opendkim-manage-go/../retention.json"
	if err := nonCanonical.Validate(); err == nil {
		t.Fatal("non-canonical retention journal path was accepted")
	}
}

func TestLoadDKIM2RejectsExternalCampaignCoupling(t *testing.T) {
	path := writeTemp(t, `
global:
  mode: dkim2
ldap:
  uri: "ldaps://ldap.example.org/ou=dkim,dc=example"
dkim2:
  tenant_id: tenant-example
  profile_use: originator
  rollout: enforce
  compatibility: strict
  campaign:
    executable: /usr/local/bin/dkim2d
`)
	if _, err := Load(path); err == nil {
		t.Fatal("accepted an external DKIM campaign executable")
	}
}

func TestValidateDKIM2RotationRangesAndDistinctProofEndpoints(t *testing.T) {
	valid := defaultConfig()
	valid.Global.Mode = types.ModeDKIM2
	valid.LDAP.URI = "ldaps://ldap.example.org/ou=dkim,dc=example"
	valid.DKIM2.TenantID = "tenant-example"
	valid.DKIM2.ProfileUse = "originator"
	valid.DKIM2.Rollout = "enforce"
	valid.DKIM2.Compatibility = "strict"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid rotation config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "rotate days", mutate: func(c *Config) { c.DKIM2.RotateAfterDays = 0 }},
		{name: "history", mutate: func(c *Config) { c.DKIM2.HistoryLimit = 1 }},
		{name: "campaign bindings", mutate: func(c *Config) { c.DKIM2.MaxCampaignBindings = 0 }},
		{name: "generation entries", mutate: func(c *Config) { c.DKIM2.MaxGenerationEntries = 0 }},
		{name: "attribute bytes", mutate: func(c *Config) { c.DKIM2.MaxAttributeBytes = 0 }},
		{name: "dataset bytes", mutate: func(c *Config) { c.DKIM2.MaxDatasetBytes = 0 }},
		{name: "LDAP requests", mutate: func(c *Config) { c.DKIM2.MaxLDAPRequests = 0 }},
		{name: "LDAP bytes", mutate: func(c *Config) { c.DKIM2.MaxLDAPBytes = c.DKIM2.MaxDatasetBytes - 1 }},
		{name: "root visits", mutate: func(c *Config) { c.DKIM2.MaxRetainedRootVisits = c.DKIM2.HistoryLimit - 1 }},
		{name: "identifier attempts", mutate: func(c *Config) { c.DKIM2.IdentifierAllocationAttempts = 0 }},
		{name: "readback attempts", mutate: func(c *Config) { c.DKIM2.PublicationReadbackAttempts = 0 }},
		{name: "readback interval", mutate: func(c *Config) { c.DKIM2.PublicationReadbackIntervalMillis = 0 }},
		{name: "LDAP search time", mutate: func(c *Config) { c.DKIM2.LDAPSearchTimeLimitSeconds = 0 }},
		{name: "LDAP operation timeout", mutate: func(c *Config) { c.DKIM2.LDAPOperationTimeoutSeconds = 0 }},
		{name: "authority password bytes", mutate: func(c *Config) { c.DKIM2.AuthorityPasswordMaxBytes = 0 }},
		{name: "skew", mutate: func(c *Config) { c.DKIM2.MaxClockSkewSeconds = 3601 }},
		{name: "run timeout", mutate: func(c *Config) { c.DKIM2.RunTimeoutSeconds = 29 }},
		{name: "poll", mutate: func(c *Config) { c.DKIM2.ProofPollIntervalSeconds = 301 }},
		{name: "attempts", mutate: func(c *Config) { c.DKIM2.ProofMaxAttempts = 0 }},
		{name: "query timeout", mutate: func(c *Config) { c.DKIM2.DNSQueryTimeoutSeconds = 31 }},
		{name: "overlap", mutate: func(c *Config) { c.DKIM2.RetirementMinOverlapSeconds = 3599 }},
		{name: "retained generations", mutate: func(c *Config) { c.DKIM2.Retention.MaxGenerations = 0 }},
		{name: "rollback reserve", mutate: func(c *Config) { c.DKIM2.Retention.MinRollbackGenerations = c.DKIM2.Retention.MaxGenerations }},
		{name: "delete batch", mutate: func(c *Config) { c.DKIM2.Retention.MaxDeleteBatch = 0 }},
		{name: "journal bytes", mutate: func(c *Config) { c.DKIM2.Retention.MaxJournalBytes = 0 }},
		{name: "same endpoint", mutate: func(c *Config) { c.DNS.RecursiveNameserver = c.DNS.PrimaryNameserver }},
		{name: "missing port", mutate: func(c *Config) { c.DNS.PrimaryNameserver = "127.0.0.1" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid DKIM2 rotation config was accepted")
			}
		})
	}
}
