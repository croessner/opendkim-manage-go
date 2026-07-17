package config

import (
	"os"
	"path/filepath"
	"testing"
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
