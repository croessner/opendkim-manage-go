package ldapstore

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type Selector struct {
	DomainName   string
	SelectorName string
	LDAPDN       string
	Created      time.Time
	Modified     time.Time
	State        types.DKIMActiveState
	RevokeState  types.DKIMRevokeState
	KeyType      types.DKIMKeyType
	Key          string
}

type Domain struct {
	LDAPDN               string
	DomainName           string
	DestinationIndicator string
	ServiceType          string
	Selectors            map[string]*Selector
}

type Tree struct {
	cfg          *config.Config
	client       *Client
	scheme       types.Scheme
	domain       string
	loaded       bool
	domains      map[string]*Domain
	domainLoader func(string) (map[string]*Domain, error)
}

func NewTree(cfg *config.Config, domain string) (*Tree, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(domain) == "" {
		domain = "*"
	}
	return &Tree{
		cfg:     cfg,
		client:  client,
		scheme:  cfg.Scheme,
		domain:  domain,
		domains: map[string]*Domain{},
	}, nil
}

func (t *Tree) Close() error {
	if t.client != nil {
		return t.client.Close()
	}
	return nil
}

func (t *Tree) SetDomainName(domain string) {
	if strings.TrimSpace(domain) == "" {
		domain = "*"
	}
	t.domain = domain
	t.loaded = false
	t.domains = map[string]*Domain{}
}

func ldapFilterValue(value string) string {
	if value == "*" {
		return value
	}
	return ldap.EscapeFilter(value)
}

func ldapSearchFilter(template, domain string) string {
	filter := strings.TrimSpace(template)
	value := ldapFilterValue(domain)
	if strings.Contains(filter, "{0}") {
		return strings.ReplaceAll(filter, "{0}", value)
	}
	if strings.Contains(filter, "%s") {
		return strings.ReplaceAll(filter, "%s", value)
	}
	return filter
}

func (t *Tree) ParseTree() error {
	domains, err := t.fetchDomains(t.domain)
	if err != nil {
		return err
	}
	t.domains = domains
	t.loaded = true
	return nil
}

func (t *Tree) fetchDomains(domain string) (map[string]*Domain, error) {
	if t.domainLoader != nil {
		return t.domainLoader(domain)
	}
	return t.loadDomains(domain)
}

func (t *Tree) loadDomains(filterDomain string) (map[string]*Domain, error) {
	attrs := []string{t.scheme.AssociatedDomain, t.scheme.DestinationIndicator, t.scheme.ServiceType}
	searchFilter := t.client.CustomSearchFilter()
	if strings.TrimSpace(searchFilter) != "" {
		searchFilter = ldapSearchFilter(searchFilter, filterDomain)
	} else {
		searchFilter = fmt.Sprintf("(&(objectClass=%s)(%s=%s))", t.scheme.DomainClass, t.scheme.AssociatedDomain, ldapFilterValue(filterDomain))
	}
	entries, err := t.client.Search(searchFilter, "", attrs, 0)
	if err != nil {
		return nil, err
	}

	domains := map[string]*Domain{}
	for _, entry := range entries {
		domainName := entry.GetAttributeValue(t.scheme.AssociatedDomain)
		if strings.TrimSpace(domainName) == "" {
			continue
		}
		domain := &Domain{
			LDAPDN:               entry.DN,
			DomainName:           domainName,
			DestinationIndicator: entry.GetAttributeValue(t.scheme.DestinationIndicator),
			ServiceType:          entry.GetAttributeValue(t.scheme.ServiceType),
			Selectors:            map[string]*Selector{},
		}

		selFilter := selectorSearchFilter(t.scheme, domainName, containsDomain(t.cfg.Global.MultipleSignaturesDomains, domainName))
		selAttrs := []string{t.scheme.DKIMDomain, t.scheme.AssociatedDomain, t.scheme.DKIMSelector, t.scheme.DKIMActive, t.scheme.CreateTimestamp, t.scheme.ModifyTimestamp, t.scheme.DKIMKeyType}
		selEntries, err := t.client.Search(selFilter, "", selAttrs, ldap.ScopeWholeSubtree)
		if err != nil {
			return nil, err
		}
		for _, se := range selEntries {
			selName := se.GetAttributeValue(t.scheme.DKIMSelector)
			if strings.TrimSpace(selName) == "" {
				continue
			}
			sel := &Selector{
				LDAPDN:       se.DN,
				DomainName:   domainName,
				SelectorName: selName,
				State:        types.DKIMDisabled,
				RevokeState:  types.RevokeDisabled,
			}
			if strings.EqualFold(se.GetAttributeValue(t.scheme.DKIMActive), "TRUE") {
				sel.State = types.DKIMEnabled
			}
			switch strings.ToLower(se.GetAttributeValue(t.scheme.DKIMKeyType)) {
			case "rsa":
				sel.KeyType = types.DKIMKeyTypeRSA
			case "ed25519":
				sel.KeyType = types.DKIMKeyTypeED25519
			}
			if ts := se.GetAttributeValue(t.scheme.CreateTimestamp); ts != "" {
				sel.Created, err = ConvertLDAPTimeToTime(ts)
				if err != nil {
					return nil, fmt.Errorf("selector %q createTimestamp: %w", selName, err)
				}
			}
			if ts := se.GetAttributeValue(t.scheme.ModifyTimestamp); ts != "" {
				sel.Modified, err = ConvertLDAPTimeToTime(ts)
				if err != nil {
					return nil, fmt.Errorf("selector %q modifyTimestamp: %w", selName, err)
				}
			}
			if sel.Modified.IsZero() {
				sel.Modified = sel.Created
			}
			if previous := domain.Selectors[selName]; previous != nil && previous.LDAPDN != sel.LDAPDN {
				return nil, fmt.Errorf("selector %q is ambiguous for domain %q", selName, domainName)
			}
			domain.Selectors[selName] = sel
		}

		domains[domainName] = domain
	}
	return domains, nil
}

func selectorSearchFilter(scheme types.Scheme, domainName string, includeWildcard bool) string {
	if !includeWildcard {
		return fmt.Sprintf("(&(objectClass=%s)(%s=%s))", scheme.DKIM, scheme.DKIMDomain, ldapFilterValue(domainName))
	}
	return fmt.Sprintf("(&(objectClass=%s)(|(%s=%s)(&(%s=%s)(%s=%s))))", scheme.DKIM, scheme.DKIMDomain, ldapFilterValue(domainName), scheme.DKIMDomain, ldap.EscapeFilter("*"), scheme.AssociatedDomain, ldapFilterValue(domainName))
}

func containsDomain(domains []string, domain string) bool {
	for _, candidate := range domains {
		if strings.EqualFold(strings.TrimSpace(candidate), domain) {
			return true
		}
	}
	return false
}

func (t *Tree) ensureLoaded() error {
	if t.loaded {
		return nil
	}
	return t.ParseTree()
}

func (t *Tree) ReloadSelectorsByDomainName(domain string) error {
	refreshed, err := t.fetchDomains(domain)
	if err != nil {
		return err
	}
	if t.domains == nil {
		t.domains = map[string]*Domain{}
	}
	if value := refreshed[domain]; value != nil {
		t.domains[domain] = value
	} else {
		delete(t.domains, domain)
	}
	t.loaded = true
	return nil
}

func (t *Tree) GetDomainNames() ([]string, error) {
	if err := t.ensureLoaded(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(t.domains))
	for k := range t.domains {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (t *Tree) GetDomainByDomainName(domainName string) (*Domain, error) {
	if err := t.ensureLoaded(); err != nil {
		return nil, err
	}
	return t.domains[domainName], nil
}

func (t *Tree) GetSelectorsByDomainName(domainName string) (map[string]*Selector, error) {
	if err := t.ensureLoaded(); err != nil {
		return nil, err
	}
	d := t.domains[domainName]
	if d == nil {
		return nil, nil
	}
	return d.Selectors, nil
}

func (t *Tree) GetSelectorByDomainName(domainName, selectorName string) (*Selector, error) {
	if err := t.ensureLoaded(); err != nil {
		return nil, err
	}
	d := t.domains[domainName]
	if d == nil {
		return nil, nil
	}
	if s := d.Selectors[selectorName]; s != nil {
		return s, nil
	}
	return nil, nil
}

func (t *Tree) GetSelector(selectorName string) (*Selector, error) {
	if err := t.ensureLoaded(); err != nil {
		return nil, err
	}
	var found *Selector
	for _, d := range t.domains {
		if s := d.Selectors[selectorName]; s != nil {
			if found != nil && found.DomainName != s.DomainName {
				return nil, fmt.Errorf("selector %q is ambiguous; specify a domain", selectorName)
			}
			found = s
		}
	}
	return found, nil
}

func (t *Tree) GetState(domainName, selectorName string) (types.DKIMActiveState, error) {
	s, err := t.GetSelectorByDomainName(domainName, selectorName)
	if err != nil || s == nil {
		return types.DKIMDisabled, err
	}
	return s.State, nil
}

func (t *Tree) GetRevokeState(domainName, selectorName string) (types.DKIMRevokeState, error) {
	s, err := t.GetSelectorByDomainName(domainName, selectorName)
	if err != nil || s == nil {
		return types.RevokeDisabled, err
	}
	if s.RevokeState == types.RevokeEnabled {
		return s.RevokeState, nil
	}
	if _, err := t.GetKey(domainName, selectorName); err != nil {
		return types.RevokeDisabled, err
	}
	return s.RevokeState, nil
}

func (t *Tree) GetCreated(domainName, selectorName string) (time.Time, error) {
	s, err := t.GetSelectorByDomainName(domainName, selectorName)
	if err != nil || s == nil {
		return time.Time{}, err
	}
	return s.Created, nil
}

func (t *Tree) GetModified(domainName, selectorName string) (time.Time, error) {
	s, err := t.GetSelectorByDomainName(domainName, selectorName)
	if err != nil || s == nil {
		return time.Time{}, err
	}
	return s.Modified, nil
}

func (t *Tree) GetKey(domainName, selectorName string) (string, error) {
	s, err := t.GetSelectorByDomainName(domainName, selectorName)
	if err != nil || s == nil {
		return "", err
	}
	if s.Key != "" {
		return s.Key, nil
	}
	if strings.TrimSpace(s.LDAPDN) == "" {
		return "", nil
	}
	entries, err := t.client.Search(fmt.Sprintf("(objectClass=%s)", t.scheme.DKIM), s.LDAPDN, []string{t.scheme.DKIMKey}, ldap.ScopeBaseObject)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", nil
	}
	key := entries[0].GetAttributeValue(t.scheme.DKIMKey)
	if key == "revoked" {
		s.RevokeState = types.RevokeEnabled
	}
	s.Key = key
	return key, nil
}

func (t *Tree) GetKeyType(domainName, selectorName string) (types.DKIMKeyType, error) {
	if err := t.ensureLoaded(); err != nil {
		return types.DKIMKeyTypeUnknown, err
	}
	if d := t.domains[domainName]; d != nil {
		if s := d.Selectors[selectorName]; s != nil && s.KeyType != types.DKIMKeyTypeUnknown {
			return s.KeyType, nil
		}
	}
	key, err := t.GetKey(domainName, selectorName)
	if err != nil {
		return types.DKIMKeyTypeUnknown, err
	}
	if key == "" {
		return types.DKIMKeyTypeUnknown, nil
	}
	if strings.HasPrefix(key, "-----BEGIN RSA PRIVATE KEY-----") { // gitleaks:allow -- PEM marker detection, not key material.
		return types.DKIMKeyTypeRSA, nil
	}
	if strings.HasPrefix(key, "-----BEGIN PRIVATE KEY-----") {
		lines := strings.Split(strings.TrimSpace(key), "\n")
		if len(lines) <= 4 {
			return types.DKIMKeyTypeED25519, nil
		}
		return types.DKIMKeyTypeRSA, nil
	}
	if key == "revoked" {
		return types.DKIMKeyTypeRevoked, nil
	}
	return types.DKIMKeyTypeUnknown, nil
}

func (t *Tree) GetSortedCreatedByDomainName(domainName string) ([][2]any, error) {
	selectors, err := t.GetSelectorsByDomainName(domainName)
	if err != nil || selectors == nil {
		return nil, err
	}
	out := make([][2]any, 0, len(selectors))
	for name, s := range selectors {
		out = append(out, [2]any{name, s.Created})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i][1].(time.Time).After(out[j][1].(time.Time))
	})
	return out, nil
}

func (t *Tree) GetSortedModifiedByDomainName(domainName string) ([][2]any, error) {
	selectors, err := t.GetSelectorsByDomainName(domainName)
	if err != nil || selectors == nil {
		return nil, err
	}
	out := make([][2]any, 0, len(selectors))
	for name, s := range selectors {
		out = append(out, [2]any{name, s.Modified})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i][1].(time.Time).After(out[j][1].(time.Time))
	})
	return out, nil
}

func (t *Tree) GetActiveSelectorsByDomainName(domainName string) ([]*Selector, error) {
	selectors, err := t.GetSelectorsByDomainName(domainName)
	if err != nil || selectors == nil {
		return nil, err
	}
	out := make([]*Selector, 0)
	for _, s := range selectors {
		if s.State == types.DKIMEnabled {
			out = append(out, s)
		}
	}
	return out, nil
}

func (t *Tree) GetDomainNamesWithEmptySelectors() ([]string, error) {
	if err := t.ensureLoaded(); err != nil {
		return nil, err
	}
	out := make([]string, 0)
	for name, d := range t.domains {
		if len(d.Selectors) == 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (t *Tree) HasDKIMKey(domainName, selectorName string) (bool, error) {
	kt, err := t.GetKeyType(domainName, selectorName)
	if err != nil {
		return false, err
	}
	switch kt {
	case types.DKIMKeyTypeRSA, types.DKIMKeyTypeED25519:
		return true, nil
	default:
		return false, nil
	}
}

func ConvertLDAPTimeToTime(ldaptime string) (time.Time, error) {
	if len(ldaptime) < 14 {
		return time.Time{}, fmt.Errorf("invalid ldap time %q", ldaptime)
	}
	raw := ldaptime[:14]
	tm, err := time.ParseInLocation("20060102150405", raw, time.UTC)
	if err != nil {
		return time.Time{}, err
	}
	return tm, nil
}
