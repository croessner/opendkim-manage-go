package ldapstore

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

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

func TestClientBaseDNReturnsValidatedURIBase(t *testing.T) {
	client := newRequestTestClient(t)
	if got := client.BaseDN(); got != "ou=dkim2,dc=example,dc=org" {
		t.Fatalf("unexpected base DN: %q", got)
	}

	cfg := &config.Config{}
	cfg.LDAP.URI = "ldaps://ldap.example.org/not-a-dn"
	if _, err := NewClient(cfg); err == nil {
		t.Fatal("expected invalid URI base DN to fail")
	}
}

func TestExactRequestValidationAcceptsBoundedRequests(t *testing.T) {
	client := newRequestTestClient(t)
	if err := client.validateSearchRequest(validSearchRequest()); err != nil {
		t.Fatalf("validate search request: %v", err)
	}
	if err := client.validateAddRequest(validAddRequest()); err != nil {
		t.Fatalf("validate add request: %v", err)
	}
	if err := client.validateModifyRequest(validModifyRequest()); err != nil {
		t.Fatalf("validate modify request: %v", err)
	}
	if client.conn != nil {
		t.Fatal("validation must not establish a connection")
	}
}

func TestSearchRequestValidationFailsBeforeConnecting(t *testing.T) {
	tests := map[string]func(*ldap.SearchRequest){
		"outside configured base": func(req *ldap.SearchRequest) { req.BaseDN = "dc=outside,dc=org" },
		"alias dereference":       func(req *ldap.SearchRequest) { req.DerefAliases = ldap.DerefAlways },
		"unbounded size":          func(req *ldap.SearchRequest) { req.SizeLimit = 0 },
		"unenforced size":         func(req *ldap.SearchRequest) { req.EnforceSizeLimit = false },
		"unbounded time":          func(req *ldap.SearchRequest) { req.TimeLimit = 0 },
		"types only":              func(req *ldap.SearchRequest) { req.TypesOnly = true },
		"invalid filter":          func(req *ldap.SearchRequest) { req.Filter = "(" },
		"no attributes":           func(req *ldap.SearchRequest) { req.Attributes = nil },
		"broad attributes":        func(req *ldap.SearchRequest) { req.Attributes = []string{"*"} },
		"duplicate attributes":    func(req *ldap.SearchRequest) { req.Attributes = []string{"cn", "CN"} },
		"nil control": func(req *ldap.SearchRequest) {
			var control *ldap.ControlString
			req.Controls = []ldap.Control{control}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client := newRequestTestClient(t)
			req := validSearchRequest()
			mutate(req)
			if _, err := client.SearchRequest(req); err == nil {
				t.Fatal("expected validation error")
			}
			if client.conn != nil {
				t.Fatal("validation failure must not establish a connection")
			}
		})
	}

	client := newRequestTestClient(t)
	if _, err := client.SearchRequest(nil); err == nil {
		t.Fatal("expected nil request to fail")
	}
}

func TestAddRequestValidationFailsBeforeConnecting(t *testing.T) {
	tests := map[string]func(*ldap.AddRequest){
		"outside configured base": func(req *ldap.AddRequest) { req.DN = "cn=entry,dc=outside,dc=org" },
		"no attributes":           func(req *ldap.AddRequest) { req.Attributes = nil },
		"invalid attribute": func(req *ldap.AddRequest) {
			req.Attributes[0].Type = "*"
		},
		"duplicate attribute": func(req *ldap.AddRequest) {
			req.Attributes = append(req.Attributes, ldap.Attribute{Type: "CN", Vals: []string{"other"}})
		},
		"no values": func(req *ldap.AddRequest) {
			req.Attributes[0].Vals = nil
		},
		"empty value": func(req *ldap.AddRequest) {
			req.Attributes[0].Vals = []string{""}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client := newRequestTestClient(t)
			req := validAddRequest()
			mutate(req)
			if err := client.AddRequest(req); err == nil {
				t.Fatal("expected validation error")
			}
			if client.conn != nil {
				t.Fatal("validation failure must not establish a connection")
			}
		})
	}

	client := newRequestTestClient(t)
	if err := client.AddRequest(nil); err == nil {
		t.Fatal("expected nil request to fail")
	}
}

func TestModifyRequestValidationFailsBeforeConnecting(t *testing.T) {
	tests := map[string]func(*ldap.ModifyRequest){
		"outside configured base": func(req *ldap.ModifyRequest) { req.DN = "cn=current,dc=outside,dc=org" },
		"no changes":              func(req *ldap.ModifyRequest) { req.Changes = nil },
		"non-replacement change": func(req *ldap.ModifyRequest) {
			req.Changes[0].Operation = ldap.DeleteAttribute
		},
		"invalid attribute": func(req *ldap.ModifyRequest) {
			req.Changes[0].Modification.Type = ""
		},
		"duplicate attribute": func(req *ldap.ModifyRequest) {
			req.Replace("DKIM2STATE", []string{"committed"})
		},
		"no values": func(req *ldap.ModifyRequest) {
			req.Changes[0].Modification.Vals = nil
		},
		"empty value": func(req *ldap.ModifyRequest) {
			req.Changes[0].Modification.Vals = []string{""}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client := newRequestTestClient(t)
			req := validModifyRequest()
			mutate(req)
			if _, err := client.ModifyRequest(req); err == nil {
				t.Fatal("expected validation error")
			}
			if client.conn != nil {
				t.Fatal("validation failure must not establish a connection")
			}
		})
	}

	client := newRequestTestClient(t)
	if _, err := client.ModifyRequest(nil); err == nil {
		t.Fatal("expected nil request to fail")
	}
}

func TestSafeRequestErrorRedactsDiagnosticsAndPreservesResultCode(t *testing.T) {
	const secretMarker = "private-key-marker"
	serverErr := ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New(secretMarker))
	err := safeRequestError("modify", serverErr)
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("request error exposed server diagnostics: %v", err)
	}
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) {
		t.Fatalf("request error lost LDAP result code: %v", err)
	}
}

func newRequestTestClient(t *testing.T) *Client {
	t.Helper()
	cfg := &config.Config{}
	cfg.LDAP.URI = "ldaps://ldap.example.org/ou=dkim2,dc=example,dc=org"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func validSearchRequest() *ldap.SearchRequest {
	req := ldap.NewSearchRequest(
		"ou=generations,ou=dkim2,dc=example,dc=org",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		100,
		30,
		false,
		"(objectClass=dkim2Generation)",
		[]string{"objectClass", "dkim2Generation"},
		nil,
	)
	req.EnforceSizeLimit = true
	return req
}

func validAddRequest() *ldap.AddRequest {
	req := ldap.NewAddRequest("cn=entry,ou=dkim2,dc=example,dc=org", nil)
	req.Attribute("cn", []string{"entry"})
	return req
}

func validModifyRequest() *ldap.ModifyRequest {
	req := ldap.NewModifyRequest("cn=current,ou=dkim2,dc=example,dc=org", nil)
	req.Replace("dkim2State", []string{"committed"})
	return req
}
