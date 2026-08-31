package ldapstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/types"
)

func TestConvertLDAPTimeToTime(t *testing.T) {
	ts, err := ConvertLDAPTimeToTime("20260314112233Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Date(2026, 3, 14, 11, 22, 33, 0, time.UTC)
	if !ts.Equal(expected) {
		t.Fatalf("unexpected time: %v", ts)
	}
}

func TestLDAPFilterValueEscapesDomainInput(t *testing.T) {
	got := ldapFilterValue(`example.org)(associatedDomain=*)`)
	want := `example.org\29\28associatedDomain=\2a\29`
	if got != want {
		t.Fatalf("unexpected escaped filter value: got %q want %q", got, want)
	}
}

func TestLDAPFilterValueKeepsWildcard(t *testing.T) {
	if got := ldapFilterValue("*"); got != "*" {
		t.Fatalf("unexpected wildcard filter value: %q", got)
	}
}

func TestLDAPSearchFilterReplacesLegacyPlaceholder(t *testing.T) {
	got := ldapSearchFilter("(&(objectClass=domain)(associatedDomain={0}))", "example.com")
	want := "(&(objectClass=domain)(associatedDomain=example.com))"
	if got != want {
		t.Fatalf("unexpected filter: got %q want %q", got, want)
	}
}

func TestLDAPSearchFilterEscapesLegacyPlaceholderValue(t *testing.T) {
	got := ldapSearchFilter("(&(objectClass=domain)(associatedDomain={0}))", `example.org)(associatedDomain=*)`)
	want := `(&(objectClass=domain)(associatedDomain=example.org\29\28associatedDomain=\2a\29))`
	if got != want {
		t.Fatalf("unexpected filter: got %q want %q", got, want)
	}
}

func TestLDAPSearchFilterSupportsPercentSPlaceholder(t *testing.T) {
	got := ldapSearchFilter("(&(objectClass=domain)(associatedDomain=%s))", "example.com")
	want := "(&(objectClass=domain)(associatedDomain=example.com))"
	if got != want {
		t.Fatalf("unexpected filter: got %q want %q", got, want)
	}
}

func TestLDAPSearchFilterAllowsStaticFilter(t *testing.T) {
	got := ldapSearchFilter("(objectClass=domain)", "example.com")
	want := "(objectClass=domain)"
	if got != want {
		t.Fatalf("unexpected filter: got %q want %q", got, want)
	}
}

func TestReloadSelectorsPreservesOtherDomains(t *testing.T) {
	tree := &Tree{
		loaded: true,
		domains: map[string]*Domain{
			"one.example": {DomainName: "one.example", Selectors: map[string]*Selector{"old": {SelectorName: "old"}}},
			"two.example": {DomainName: "two.example", Selectors: map[string]*Selector{"keep": {SelectorName: "keep"}}},
		},
		domainLoader: func(domain string) (map[string]*Domain, error) {
			return map[string]*Domain{
				domain: {DomainName: domain, Selectors: map[string]*Selector{"new": {SelectorName: "new"}}},
			}, nil
		},
	}

	if err := tree.ReloadSelectorsByDomainName("one.example"); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if tree.domains["two.example"] == nil || tree.domains["two.example"].Selectors["keep"] == nil {
		t.Fatal("reload discarded an unrelated domain")
	}
	if tree.domains["one.example"].Selectors["new"] == nil {
		t.Fatal("target domain was not refreshed")
	}
}

func TestGetSelectorRejectsCrossDomainAmbiguity(t *testing.T) {
	tree := &Tree{
		loaded: true,
		domains: map[string]*Domain{
			"one.example": {DomainName: "one.example", Selectors: map[string]*Selector{"selector-rsa-1": {DomainName: "one.example", SelectorName: "selector-rsa-1"}}},
			"two.example": {DomainName: "two.example", Selectors: map[string]*Selector{"selector-rsa-1": {DomainName: "two.example", SelectorName: "selector-rsa-1"}}},
		},
	}
	if _, err := tree.GetSelector("selector-rsa-1"); err == nil {
		t.Fatal("expected ambiguous global selector lookup to fail")
	}
}

func TestGetSelectorByDomainNameReturnsNilWhenMissing(t *testing.T) {
	tree := &Tree{loaded: true, domains: map[string]*Domain{"example.org": {DomainName: "example.org", Selectors: map[string]*Selector{}}}}
	selector, err := tree.GetSelectorByDomainName("example.org", "missing")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if selector != nil {
		t.Fatalf("expected nil selector, got %#v", selector)
	}
}

func TestGetKeyConvergesWhenSelectorDisappearsAfterTreeLoad(t *testing.T) {
	const domainName = "example.org"
	const selectorName = "selector-rsa-1"
	tree := &Tree{
		loaded: true,
		domains: map[string]*Domain{
			domainName: {
				DomainName: domainName,
				Selectors: map[string]*Selector{
					selectorName: {
						DomainName:   domainName,
						SelectorName: selectorName,
						LDAPDN:       "DKIMSelector=selector-rsa-1,dc=example,dc=org",
					},
				},
			},
		},
		domainLoader: func(domain string) (map[string]*Domain, error) {
			return map[string]*Domain{
				domain: {DomainName: domain, Selectors: map[string]*Selector{}},
			}, nil
		},
		keyLoader: func(*Selector) (string, error) {
			return "", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
		},
	}

	if _, err := tree.GetKey(domainName, selectorName); !errors.Is(err, ErrSelectorDisappeared) {
		t.Fatalf("unexpected key lookup error: %v", err)
	}
	selector, err := tree.GetSelectorByDomainName(domainName, selectorName)
	if err != nil {
		t.Fatalf("selector lookup failed: %v", err)
	}
	if selector != nil {
		t.Fatalf("stale selector survived authoritative reload: %#v", selector)
	}
}

func TestGetKeyRetriesWithRefreshedSelectorDN(t *testing.T) {
	const domainName = "example.org"
	const selectorName = "selector-rsa-1"
	loads := 0
	tree := &Tree{
		loaded: true,
		domains: map[string]*Domain{
			domainName: {
				DomainName: domainName,
				Selectors: map[string]*Selector{
					selectorName: {DomainName: domainName, SelectorName: selectorName, LDAPDN: "old-dn"},
				},
			},
		},
		domainLoader: func(domain string) (map[string]*Domain, error) {
			return map[string]*Domain{
				domain: {
					DomainName: domain,
					Selectors: map[string]*Selector{
						selectorName: {DomainName: domain, SelectorName: selectorName, LDAPDN: "new-dn"},
					},
				},
			}, nil
		},
		keyLoader: func(selector *Selector) (string, error) {
			loads++
			if selector.LDAPDN == "old-dn" {
				return "", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("renamed"))
			}
			return "revoked", nil
		},
	}

	key, err := tree.GetKey(domainName, selectorName)
	if err != nil {
		t.Fatalf("key lookup failed after refresh: %v", err)
	}
	if key != "revoked" || loads != 2 {
		t.Fatalf("unexpected refreshed key result: key=%q loads=%d", key, loads)
	}
	selector, err := tree.GetSelectorByDomainName(domainName, selectorName)
	if err != nil || selector == nil || selector.LDAPDN != "new-dn" || selector.RevokeState != types.RevokeEnabled {
		t.Fatalf("refreshed selector state mismatch: selector=%#v err=%v", selector, err)
	}
}

func TestSelectorSearchFilterMatchesLiteralWildcardDomain(t *testing.T) {
	filter := selectorSearchFilter(types.DefaultScheme(), "example.org")
	if !strings.Contains(filter, "(DKIMDomain=example.org)") {
		t.Fatalf("filter does not match the exact signing domain: %s", filter)
	}
	if !strings.Contains(filter, "(DKIMDomain=\\2a)") {
		t.Fatalf("filter does not match literal wildcard: %s", filter)
	}
	if !strings.Contains(filter, "(associatedDomain=example.org)") {
		t.Fatalf("filter lost associatedDomain constraint: %s", filter)
	}
}
