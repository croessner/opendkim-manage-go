package ldapstore

import (
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

func TestTLSConfigUsesLDAPURIHostAsServerName(t *testing.T) {
	cfg := &config.Config{}
	cfg.LDAP.URI = "ldap://ldap.example.com:389/ou=dkim,dc=example??sub?(objectClass=domain)"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	tlsCfg, err := client.buildTLSConfig()
	if err != nil {
		t.Fatalf("build TLS config: %v", err)
	}
	if tlsCfg.ServerName != "ldap.example.com" {
		t.Fatalf("unexpected server name: %q", tlsCfg.ServerName)
	}
}

func TestTLSConfigUsesBracketedIPv6URIHostAsServerName(t *testing.T) {
	cfg := &config.Config{}
	cfg.LDAP.URI = "ldap://[2001:db8::1]:389/ou=dkim,dc=example"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	tlsCfg, err := client.buildTLSConfig()
	if err != nil {
		t.Fatalf("build TLS config: %v", err)
	}
	if tlsCfg.ServerName != "2001:db8::1" {
		t.Fatalf("unexpected server name: %q", tlsCfg.ServerName)
	}
}
