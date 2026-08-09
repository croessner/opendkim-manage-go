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
	valid.DKIM2 = DKIM2Config{
		TenantID:        "tenant-example",
		ProfileUse:      "originator",
		Rollout:         "enforce",
		Compatibility:   "strict",
		RotateAfterDays: 365, HistoryLimit: 1024, MaxClockSkewSeconds: 300,
		RunTimeoutSeconds: 900, ProofPollIntervalSeconds: 5, ProofMaxAttempts: 60,
		DNSQueryTimeoutSeconds: 5, RetirementMinOverlapSeconds: 604800,
	}
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
	if cfg.DKIM2.RotationEnabled || cfg.DKIM2.RotateAfterDays != 365 || cfg.DKIM2.HistoryLimit != 1024 ||
		cfg.DKIM2.MaxClockSkewSeconds != 300 || cfg.DKIM2.RunTimeoutSeconds != 900 ||
		cfg.DKIM2.ProofPollIntervalSeconds != 5 || cfg.DKIM2.ProofMaxAttempts != 60 ||
		cfg.DKIM2.DNSQueryTimeoutSeconds != 5 || cfg.DKIM2.RetirementMinOverlapSeconds != 604800 {
		t.Fatalf("unexpected DKIM2 rotation defaults: %#v", cfg.DKIM2)
	}
	if cfg.DNS.PrimaryNameserver != "127.0.0.1:53" || cfg.DNS.RecursiveNameserver != "127.0.0.2:53" {
		t.Fatalf("unexpected proof endpoints: %#v", cfg.DNS)
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
		{name: "skew", mutate: func(c *Config) { c.DKIM2.MaxClockSkewSeconds = 3601 }},
		{name: "run timeout", mutate: func(c *Config) { c.DKIM2.RunTimeoutSeconds = 29 }},
		{name: "poll", mutate: func(c *Config) { c.DKIM2.ProofPollIntervalSeconds = 301 }},
		{name: "attempts", mutate: func(c *Config) { c.DKIM2.ProofMaxAttempts = 0 }},
		{name: "query timeout", mutate: func(c *Config) { c.DKIM2.DNSQueryTimeoutSeconds = 31 }},
		{name: "overlap", mutate: func(c *Config) { c.DKIM2.RetirementMinOverlapSeconds = 3599 }},
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
