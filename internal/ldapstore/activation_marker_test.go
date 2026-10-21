package ldapstore

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

// TestActivationMarkerTransportBoundary limits attribute addition to one guarded activation marker.
func TestActivationMarkerTransportBoundary(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Client, *ldap.ModifyRequest)
		valid  bool
	}{
		{name: "activation marker", valid: true},
		{name: "ordinary client", mutate: func(c *Client, _ *ldap.ModifyRequest) { c.authority = nil }},
		{name: "snapshot", mutate: func(c *Client, _ *ldap.ModifyRequest) { c.purpose = AuthoritySnapshot }},
		{name: "staging", mutate: func(c *Client, _ *ldap.ModifyRequest) { c.purpose = AuthorityStaging }},
		{name: "purge", mutate: func(c *Client, _ *ldap.ModifyRequest) { c.purpose = AuthorityPurge }},
		{name: "current", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.DN = "cn=current,ou=dkim2,dc=example,dc=org" }},
		{name: "generation child", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.DN = "cn=child," + r.DN }},
		{name: "zero", mutate: func(_ *Client, r *ldap.ModifyRequest) {
			r.DN = "dkim2Generation=0,ou=generations,ou=dkim2,dc=example,dc=org"
		}},
		{name: "noncanonical number", mutate: func(_ *Client, r *ldap.ModifyRequest) {
			r.DN = "dkim2Generation=02,ou=generations,ou=dkim2,dc=example,dc=org"
		}},
		{name: "multivalued RDN", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.DN = "cn=other+" + r.DN }},
		{name: "outside base", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.DN = "dkim2Generation=2,ou=generations,dc=other,dc=org" }},
		{name: "other attribute", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Changes[0].Modification.Type = "dkim2State" }},
		{name: "marker option", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Changes[0].Modification.Type = "dkim2WasActive;option" }},
		{name: "false marker", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Changes[0].Modification.Vals = []string{"FALSE"} }},
		{name: "multiple values", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Changes[0].Modification.Vals = []string{"TRUE", "TRUE"} }},
		{name: "second operation", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Replace("dkim2State", []string{"committed"}) }},
		{name: "delete", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Changes[0].Operation = ldap.DeleteAttribute }},
		{name: "missing assertion", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Controls = nil }},
		{name: "noncritical assertion", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Controls[0].(*ldap.ControlString).Criticality = false }},
		{name: "empty assertion", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Controls[0].(*ldap.ControlString).ControlValue = "" }},
		{name: "unrelated control", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Controls[0].(*ldap.ControlString).ControlType = "1.2.3" }},
		{name: "multiple controls", mutate: func(_ *Client, r *ldap.ModifyRequest) { r.Controls = append(r.Controls, r.Controls[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newRequestTestClient(t)
			client.authority = &config.DKIM2LDAPAuthority{BindDN: "cn=activator,dc=example,dc=org"}
			client.purpose = AuthorityActivation
			filter, err := ldap.CompileFilter("(&(dkim2Generation=2)(!(dkim2WasActive=*)))")
			if err != nil {
				t.Fatal(err)
			}
			request := ldap.NewModifyRequest("dkim2Generation=2,ou=generations,"+client.BaseDN(), []ldap.Control{
				ldap.NewControlString("1.3.6.1.1.12", true, string(filter.Bytes())),
			})
			request.Add("dkim2WasActive", []string{"TRUE"})
			if test.mutate != nil {
				test.mutate(client, request)
			}
			err = client.validateModifyRequest(request)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
			if !test.valid {
				if _, err := client.ModifyRequest(request); err == nil {
					t.Fatal("invalid request accepted")
				}
				if client.conn != nil {
					t.Fatal("invalid request opened a connection")
				}
			}
		})
	}
}
