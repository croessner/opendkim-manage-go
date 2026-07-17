package app

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
	"github.com/croessner/opendkim-manage-go/internal/selector"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type RuntimeConfig struct {
	DeleteDelay                int
	ExpireAfter                int
	MaxRevoked                 int
	RevokedRetention           int
	KeyType                    types.DKIMKeyType
	CNAMESelectorRSAPrefix     string
	CNAMESelectorED25519Prefix string
	UseDKIMIdentity            bool
	SelectorFormat             string
	MultipleSignaturesDomains  map[string]struct{}
}

type RunResult struct {
	AgeMatched *bool
}

type Manager struct {
	cfg             *config.Config
	opts            *cli.Options
	runtime         RuntimeConfig
	ldap            *ldapstore.Client
	tree            *ldapstore.Tree
	dns             *dnsupdate.Client
	lookupTXT       func(string) ([]string, error)
	writeAuthorized bool
}

var errConfirmationRequired = errors.New("confirmation required; use --yes for non-interactive writes or --interactive")

func NewManager(cfg *config.Config, opts *cli.Options) (*Manager, error) {
	ldapClient, err := ldapstore.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	tree, err := ldapstore.NewTree(cfg, "*")
	if err != nil {
		return nil, err
	}

	runtime := RuntimeConfig{
		DeleteDelay:                cfg.Global.DeleteDelay,
		ExpireAfter:                cfg.Global.ExpireAfter,
		MaxRevoked:                 cfg.Global.MaxRevoked,
		RevokedRetention:           cfg.Global.RevokedRetention,
		KeyType:                    cfg.KeyType,
		CNAMESelectorRSAPrefix:     cfg.Global.CNAMESelectorRSAPrefix,
		CNAMESelectorED25519Prefix: cfg.Global.CNAMESelectorED25519Prefix,
		UseDKIMIdentity:            cfg.Global.UseDKIMIdentity,
		SelectorFormat:             cfg.Global.SelectorFormat,
		MultipleSignaturesDomains:  map[string]struct{}{},
	}
	for _, d := range cfg.Global.MultipleSignaturesDomains {
		runtime.MultipleSignaturesDomains[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	if opts.ExpireAfter != nil {
		runtime.ExpireAfter = *opts.ExpireAfter
	}
	if opts.DeleteDelay != nil {
		runtime.DeleteDelay = *opts.DeleteDelay
	}
	if opts.MaxRevokedSet {
		runtime.MaxRevoked = opts.MaxRevoked
	}
	runtime.KeyType = opts.EffectiveKeyType(runtime.KeyType)

	m := &Manager{cfg: cfg, opts: opts, runtime: runtime, ldap: ldapClient, tree: tree}
	if opts.UpdateDNS {
		if !cfg.AuthenticatedDNSUpdatesConfigured() {
			return nil, fmt.Errorf("dns.update requested but nameserver, positive ttl, tsig_key_name, and tsig_key_file are not fully configured")
		}
		m.dns, err = dnsupdate.New(cfg)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) Close() error {
	var errs []error
	if m.ldap != nil {
		errs = append(errs, m.ldap.Close())
	}
	if m.tree != nil {
		errs = append(errs, m.tree.Close())
	}
	return errors.Join(errs...)
}

func (m *Manager) Run() (*RunResult, error) {
	result := &RunResult{}
	if m.isMutatingCommand() && !m.opts.Interactive {
		if err := m.authorizeWrites(); err != nil {
			return nil, err
		}
	}

	switch {
	case m.opts.List:
		return result, m.CmdList()
	case m.opts.PrintDNS:
		return result, m.CmdPrintDNS()
	case m.opts.Create:
		return result, m.CmdCreate("", types.DKIMKeyTypeUnknown)
	case m.opts.Delete:
		return result, m.CmdDelete("", "", m.opts.ForceDelete)
	case m.opts.Age != nil:
		matched, err := m.CmdAge(nil, nil, "")
		if err != nil {
			return nil, err
		}
		result.AgeMatched = &matched
		return result, nil
	case m.opts.Active:
		domainName := ""
		if len(m.opts.Domains) == 1 {
			domainName = m.opts.Domains[0]
		}
		return result, m.CmdActive("", domainName)
	case m.opts.TestKey:
		_, err := m.CmdTestKey(nil, "")
		return result, err
	case m.opts.Rotate:
		return result, m.CmdRotate()
	case m.opts.AddNew:
		return result, m.CmdAddNew()
	case m.opts.AddMissing:
		return result, m.CmdAddMissing()
	case m.opts.Auto:
		return result, m.CmdAuto()
	default:
		return result, nil
	}
}

func (m *Manager) CmdList() error {
	domains, err := m.inputDomainsOrAll()
	if err != nil {
		return err
	}
	for _, domainName := range domains {
		d, err := m.tree.GetDomainByDomainName(domainName)
		if err != nil {
			return err
		}
		if d == nil || d.LDAPDN == "" {
			continue
		}
		fmt.Printf("DNS domain '%s':\n", domainName)
		fmt.Printf("DN: %s\n", d.LDAPDN)

		selectorNames := make([]string, 0, len(d.Selectors))
		for name := range d.Selectors {
			selectorNames = append(selectorNames, name)
		}
		sort.Strings(selectorNames)
		for _, selectorName := range selectorNames {
			state, err := m.tree.GetState(domainName, selectorName)
			if err != nil {
				return err
			}
			revokeState, err := m.tree.GetRevokeState(domainName, selectorName)
			if err != nil {
				return err
			}
			keyType, err := m.tree.GetKeyType(domainName, selectorName)
			if err != nil {
				return err
			}
			created, err := m.tree.GetCreated(domainName, selectorName)
			if err != nil {
				return err
			}
			if created.IsZero() {
				continue
			}
			tags := make([]string, 0)
			if state == types.DKIMEnabled {
				tags = append(tags, "active")
			}
			if revokeState == types.RevokeEnabled {
				tags = append(tags, "revoked")
			}
			tag := ""
			if len(tags) > 0 {
				tag = " [" + strings.Join(tags, ",") + "]"
			}
			fmt.Printf("%s DKIMSelector: %s %s%s\n", created.Local().Format("2006-01-02 15:04:05"), selectorName, keyType.String(), tag)
		}
	}
	return nil
}

func (m *Manager) CmdCreate(domainName string, explicitType types.DKIMKeyType) error {
	domains := m.opts.Domains
	if domainName != "" {
		domains = []string{domainName}
	}

	if len(m.opts.Selectors) > 0 {
		if len(domains) > 1 {
			return fmt.Errorf("manual create accepts only one domain")
		}
		if len(m.opts.Selectors) > 1 {
			return fmt.Errorf("manual create accepts only one selector")
		}
		if m.runtime.KeyType == types.DKIMKeyTypeBoth && explicitType == types.DKIMKeyTypeUnknown {
			return fmt.Errorf("manual create requires exactly one keytype")
		}
	}

	for _, dName := range domains {
		domain, err := m.tree.GetDomainByDomainName(dName)
		if err != nil {
			return err
		}
		if domain == nil {
			m.warnf("domain %q does not exist in LDAP", dName)
			continue
		}
		if err := m.validateDomainForMutation(dName, domain); err != nil {
			return err
		}

		keyTypes := m.keyTypesForCreate(explicitType)
		for _, keyType := range keyTypes {
			newSelector, err := m.resolveNewSelectorName(dName)
			if err != nil {
				return err
			}
			if _, exists := domain.Selectors[newSelector]; exists {
				return fmt.Errorf("selector %q already exists for domain %q", newSelector, dName)
			}

			dk := dkim.NewKeys()
			if keyType == types.DKIMKeyTypeRSA {
				if err := dk.SetRSABits(m.opts.Size); err != nil {
					return err
				}
				if err := dk.GenerateRSA(); err != nil {
					return err
				}
			} else {
				if err := dk.GenerateED25519(); err != nil {
					return err
				}
			}

			privateKey := privateKeyByType(dk, keyType)
			publicKey := publicKeyByType(dk, keyType)
			ok, err := m.confirm("Do you want to save the DKIM key in LDAP?")
			if err != nil {
				return err
			}
			if !ok {
				continue
			}

			var identity *string
			if m.runtime.UseDKIMIdentity {
				val := "@" + dName
				identity = &val
			}
			signingTableDomain := dName
			if _, ok := m.runtime.MultipleSignaturesDomains[strings.ToLower(strings.TrimSpace(dName))]; ok {
				signingTableDomain = "*"
			}
			dn := fmt.Sprintf("%s=%s,%s", m.cfg.Scheme.DKIMSelector, newSelector, domain.LDAPDN)
			if err := m.storeDKIMKey(dn, privateKey, keyType, dName, signingTableDomain, identity); err != nil {
				return err
			}
			if m.opts.DryRun {
				now := time.Now().UTC()
				domain.Selectors[newSelector] = &ldapstore.Selector{
					DomainName: dName, SelectorName: newSelector, LDAPDN: dn, Created: now, Modified: now,
					State: types.DKIMDisabled, RevokeState: types.RevokeDisabled, KeyType: keyType, Key: privateKey,
				}
			}
			m.verbosef("DN %s created (%s)", dn, keyType.String())

			if m.opts.UpdateDNS && domain.DestinationIndicator == "" {
				content, err := dkimTXTContent(keyType, domain.ServiceType, publicKey)
				if err != nil {
					return err
				}
				if err := m.addDNSDKIMKey(dName, newSelector, content, ""); err != nil {
					return err
				}
			}
		}
		if !m.opts.DryRun {
			if err := m.tree.ReloadSelectorsByDomainName(dName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) CmdDelete(domainName, selectorName string, forceDelete bool) error {
	selectors := []string{}
	if selectorName != "" {
		selectors = append(selectors, selectorName)
	} else if domainName != "" {
		mmap, err := m.tree.GetSelectorsByDomainName(domainName)
		if err != nil {
			return err
		}
		for s := range mmap {
			selectors = append(selectors, s)
		}
	} else {
		selectors = append(selectors, m.opts.Selectors...)
	}

	domainNames := []string{}
	if domainName != "" {
		domainNames = append(domainNames, domainName)
	} else if len(m.opts.Domains) > 0 {
		domainNames = append(domainNames, m.opts.Domains...)
	} else {
		all, err := m.tree.GetDomainNames()
		if err != nil {
			return err
		}
		domainNames = append(domainNames, all...)
	}

	if len(selectors) == 0 && len(domainNames) == 1 {
		mmap, err := m.tree.GetSelectorsByDomainName(domainNames[0])
		if err != nil {
			return err
		}
		for s := range mmap {
			selectors = append(selectors, s)
		}
	}
	if !forceDelete {
		forceDelete = m.opts.ForceDelete
	}

	needReload := map[string]struct{}{}
	for _, selectorName := range selectors {
		selector, resolvedDomain, err := m.resolveSelector(selectorName, domainName, domainNames)
		if err != nil {
			return err
		}
		if selector == nil || selector.SelectorName == "" {
			m.warnf("selector %q does not exist", selectorName)
			continue
		}

		if !forceDelete {
			state, err := m.tree.GetState(selector.DomainName, selectorName)
			if err != nil {
				return err
			}
			if state == types.DKIMEnabled {
				m.warnf("cannot remove active selector %q", selectorName)
				continue
			}
		}

		dnsDelete := func() error {
			if !m.opts.UpdateDNS {
				return nil
			}
			d, err := m.tree.GetDomainByDomainName(resolvedDomain)
			if err != nil {
				return err
			}
			zone := resolvedDomain
			subdomain := ""
			if d != nil && d.DestinationIndicator != "" {
				zone, subdomain, err = m.cnameTarget(d)
				if err != nil {
					return err
				}
			}
			return m.removeDNSDKIMKey(zone, selectorName, subdomain)
		}

		dnsRevoke := func(content string) error {
			if !m.opts.UpdateDNS {
				return nil
			}
			d, err := m.tree.GetDomainByDomainName(resolvedDomain)
			if err != nil {
				return err
			}
			zone := resolvedDomain
			subdomain := ""
			if d != nil && d.DestinationIndicator != "" {
				zone, subdomain, err = m.cnameTarget(d)
				if err != nil {
					return err
				}
			}
			return m.changeDNSDKIMKey(zone, selectorName, content, subdomain)
		}

		if forceDelete {
			ok, err := m.confirm("Do you really want to delete the DKIM key from LDAP?")
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if err := dnsDelete(); err != nil {
				return fmt.Errorf("dns delete failed for %s: %w", selectorName, err)
			}
			if err := m.deleteDKIMKey(selector.LDAPDN); err != nil {
				return err
			}
			if m.opts.DryRun {
				if domain, getErr := m.tree.GetDomainByDomainName(resolvedDomain); getErr != nil {
					return getErr
				} else if domain != nil {
					delete(domain.Selectors, selectorName)
				}
			}
			needReload[resolvedDomain] = struct{}{}
			continue
		}

		if !selector.Modified.IsZero() && selector.Modified.AddDate(0, 0, m.runtime.DeleteDelay).Before(time.Now().UTC()) {
			rev, err := m.tree.GetRevokeState(resolvedDomain, selectorName)
			if err != nil {
				return err
			}
			if rev == types.RevokeDisabled {
				kt, err := m.tree.GetKeyType(resolvedDomain, selectorName)
				if err != nil {
					return err
				}
				content, err := dkimTXTContent(kt, "", "")
				if err != nil {
					return err
				}
				if err := dnsRevoke(content); err != nil {
					return fmt.Errorf("dns revoke failed for %s: %w", selectorName, err)
				}
				if err := m.revokeDKIMKey(selector.LDAPDN); err != nil {
					return err
				}
				if m.opts.DryRun {
					selector.Key = "revoked"
					selector.RevokeState = types.RevokeEnabled
					selector.Modified = time.Now().UTC()
				}
				needReload[resolvedDomain] = struct{}{}
			}
		} else {
			m.verbosef("DN %s not deleted", selector.LDAPDN)
		}
	}

	for domain := range needReload {
		if m.opts.DryRun {
			continue
		}
		if err := m.tree.ReloadSelectorsByDomainName(domain); err != nil {
			return err
		}
	}

	for _, dName := range domainNames {
		domain, err := m.tree.GetDomainByDomainName(dName)
		if err != nil {
			return err
		}
		if domain != nil && domain.DestinationIndicator != "" {
			continue
		}
		sortedSelectors, err := m.tree.GetSortedModifiedByDomainName(dName)
		if err != nil {
			return err
		}
		revoked := make([]*ldapstore.Selector, 0)
		for _, pair := range sortedSelectors {
			sel := pair[0].(string)
			rev, err := m.tree.GetRevokeState(dName, sel)
			if err != nil {
				return err
			}
			if rev == types.RevokeEnabled {
				target, err := m.tree.GetSelectorByDomainName(dName, sel)
				if err != nil {
					return err
				}
				if target != nil && target.SelectorName != "" {
					revoked = append(revoked, target)
				}
			}
		}
		for i, target := range revoked {
			if !shouldDeleteRevoked(target.Modified, i, m.runtime.RevokedRetention, m.runtime.MaxRevoked, time.Now().UTC()) {
				continue
			}
			if m.opts.UpdateDNS {
				if err := m.removeDNSDKIMKey(dName, target.SelectorName, ""); err != nil {
					return err
				}
			}
			if err := m.deleteDKIMKey(target.LDAPDN); err != nil {
				return err
			}
			if m.opts.DryRun {
				delete(domain.Selectors, target.SelectorName)
			}
		}
		if !m.opts.DryRun {
			if err := m.tree.ReloadSelectorsByDomainName(dName); err != nil {
				return err
			}
		}
	}

	return nil
}

func shouldDeleteRevoked(modified time.Time, index, retentionDays, maxRevoked int, now time.Time) bool {
	if retentionDays > 0 {
		return !modified.IsZero() && !modified.AddDate(0, 0, retentionDays).After(now)
	}
	return index >= maxRevoked
}

func (m *Manager) CmdAge(days *int, daysDelta *time.Duration, selectorName string) (bool, error) {
	if selectorName == "" {
		if len(m.opts.Selectors) != 1 {
			return false, fmt.Errorf("--age requires exactly one --selectorname")
		}
		selectorName = m.opts.Selectors[0]
	}
	var sel *ldapstore.Selector
	var err error
	if len(m.opts.Domains) == 1 {
		sel, err = m.tree.GetSelectorByDomainName(m.opts.Domains[0], selectorName)
	} else {
		sel, err = m.tree.GetSelector(selectorName)
	}
	if err != nil {
		return false, err
	}
	if sel == nil {
		return false, fmt.Errorf("selector %q does not exist", selectorName)
	}

	cmpAge := 0
	if days != nil {
		cmpAge = *days
	} else if m.opts.Age != nil {
		cmpAge = *m.opts.Age
	} else {
		cmpAge = m.runtime.ExpireAfter
	}

	delta := time.Duration(0)
	if daysDelta != nil {
		delta = *daysDelta
	} else {
		if cmpAge < 0 {
			cmpAge = -cmpAge
		}
		delta = time.Duration(cmpAge) * 24 * time.Hour
	}
	age := time.Since(sel.Created)
	if m.opts.Age != nil && *m.opts.Age < 0 {
		return age <= delta, nil
	}
	return age >= delta, nil
}

func (m *Manager) CmdActive(selectorName, domainName string) error {
	if selectorName == "" {
		if len(m.opts.Selectors) != 1 {
			return fmt.Errorf("--active requires exactly one --selectorname")
		}
		selectorName = m.opts.Selectors[0]
	}

	var sel *ldapstore.Selector
	var err error
	if domainName != "" {
		sel, err = m.tree.GetSelectorByDomainName(domainName, selectorName)
	} else {
		sel, err = m.tree.GetSelector(selectorName)
	}
	if err != nil {
		return err
	}
	if sel == nil || sel.SelectorName == "" {
		return fmt.Errorf("selector %q does not exist", selectorName)
	}

	keyType, err := m.tree.GetKeyType(sel.DomainName, selectorName)
	if err != nil {
		return err
	}
	dnsValid := false
	if m.opts.DryRun && m.opts.UpdateDNS {
		m.dryRunf("would verify planned DNS key before activating selector=%s domain=%s", selectorName, sel.DomainName)
		dnsValid = true
	} else {
		result, testErr := m.CmdTestKey([]string{selectorName}, sel.DomainName)
		if testErr != nil {
			return testErr
		}
		dnsValid = result[selectorName]
	}
	if !dnsValid && !m.opts.ForceActive {
		if m.opts.Active {
			m.warnf("not activating selector %q because DNS record is missing or invalid", selectorName)
		}
		return nil
	}

	active, err := m.tree.GetActiveSelectorsByDomainName(sel.DomainName)
	if err != nil {
		return err
	}
	ok, err := m.confirm("Do you want to enable this DKIM key?")
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if sel.State != types.DKIMEnabled {
		if err := m.setActive(sel.LDAPDN, true); err != nil {
			return err
		}
		if m.opts.DryRun {
			sel.State = types.DKIMEnabled
		}
	}

	for _, current := range active {
		if current.SelectorName == sel.SelectorName {
			continue
		}
		curType, err := m.tree.GetKeyType(current.DomainName, current.SelectorName)
		if err != nil {
			return err
		}
		if curType != keyType {
			continue
		}
		ok, err := m.confirm("Do you really want to disable this DKIM key?")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := m.setActive(current.LDAPDN, false); err != nil {
			return err
		}
		if m.opts.DryRun {
			current.State = types.DKIMDisabled
		}
	}
	if m.opts.DryRun {
		return nil
	}
	return m.tree.ReloadSelectorsByDomainName(sel.DomainName)
}

func (m *Manager) CmdTestKey(selectorList []string, domainName string) (map[string]bool, error) {
	type target struct {
		selector   string
		domain     string
		privateKey string
	}
	targets := make([]target, 0)

	appendTarget := func(dName, selectorName string) error {
		var sel *ldapstore.Selector
		var err error
		if dName != "" {
			sel, err = m.tree.GetSelectorByDomainName(dName, selectorName)
		} else {
			sel, err = m.tree.GetSelector(selectorName)
		}
		if err != nil {
			return err
		}
		if sel == nil {
			m.warnf("selector %q does not exist", selectorName)
			return nil
		}
		key, err := m.tree.GetKey(sel.DomainName, sel.SelectorName)
		if err != nil {
			return err
		}
		if key == "" || key == "revoked" {
			return nil
		}
		targets = append(targets, target{selector: selectorName, domain: sel.DomainName, privateKey: key})
		return nil
	}

	if len(selectorList) > 0 {
		for _, selectorName := range selectorList {
			if err := appendTarget(domainName, selectorName); err != nil {
				return nil, err
			}
		}
	} else if len(m.opts.Domains) > 0 {
		for _, dName := range m.opts.Domains {
			selectors, err := m.tree.GetSelectorsByDomainName(dName)
			if err != nil {
				return nil, err
			}
			for selectorName := range selectors {
				if err := appendTarget(dName, selectorName); err != nil {
					return nil, err
				}
			}
		}
	} else {
		for _, selectorName := range m.opts.Selectors {
			if err := appendTarget("", selectorName); err != nil {
				return nil, err
			}
		}
	}

	result := make(map[string]bool, len(targets))
	seen := make(map[string]bool, len(targets))
	lookupTXT := net.LookupTXT
	if m.lookupTXT != nil {
		lookupTXT = m.lookupTXT
	}
	for _, target := range targets {
		if !seen[target.selector] {
			result[target.selector] = true
			seen[target.selector] = true
		}
		matched := false
		dnsQuery := fmt.Sprintf("%s._domainkey.%s", target.selector, target.domain)
		if m.opts.TestKey {
			fmt.Printf("Query %s\n", dnsQuery)
		}

		txt, err := lookupTXT(dnsQuery)
		if err != nil {
			m.warnf("%s TXT lookup failed: %v", dnsQuery, err)
		} else {
			kField, pField, parseErr := parseDKIMTXTRecords(txt)
			if parseErr != nil {
				m.warnf("%s invalid DKIM TXT response: %v", dnsQuery, parseErr)
			} else {
				if m.opts.TestKey {
					fmt.Printf("TXT: %s\n", txt[0])
				}
				dk := dkim.NewKeys()
				tmpPub := ""
				switch kField {
				case "rsa":
					if err := dk.GeneratePublicRSA(target.privateKey); err != nil {
						return nil, fmt.Errorf("derive RSA public key for %s: %w", dnsQuery, err)
					}
					tmpPub = dk.RSAPublicKey()
				case "ed25519":
					if err := dk.GeneratePublicED25519(target.privateKey); err != nil {
						return nil, fmt.Errorf("derive Ed25519 public key for %s: %w", dnsQuery, err)
					}
					tmpPub = dk.ED25519PublicKey()
				}
				matched = pField != "" && pField == tmpPub
			}
		}
		result[target.selector] = result[target.selector] && matched
		if matched {
			m.verbosef("%s: DNS record OK", dnsQuery)
		} else {
			m.verbosef("%s: DNS record does not match LDAP private key", dnsQuery)
		}
	}

	return result, nil
}

func parseDKIMTXTRecords(records []string) (string, string, error) {
	if len(records) != 1 {
		return "", "", fmt.Errorf("expected exactly one DKIM TXT RR, got %d", len(records))
	}
	var keyType, publicKey string
	for _, part := range strings.Split(records[0], ";") {
		field := strings.TrimSpace(part)
		if strings.HasPrefix(field, "k=") {
			keyType = strings.TrimSpace(strings.TrimPrefix(field, "k="))
		}
		if strings.HasPrefix(field, "p=") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(field, "p="))
		}
	}
	return keyType, publicKey, nil
}

func (m *Manager) CmdRotate() error {
	domains, err := m.inputDomainsOrAll()
	if err != nil {
		return err
	}
	for _, domainName := range domains {
		sortedSelectors, err := m.tree.GetSortedCreatedByDomainName(domainName)
		if err != nil {
			return err
		}
		active, err := m.tree.GetActiveSelectorsByDomainName(domainName)
		if err != nil {
			return err
		}

		activeByType := map[types.DKIMKeyType]*ldapstore.Selector{}
		for _, a := range active {
			kt, err := m.tree.GetKeyType(domainName, a.SelectorName)
			if err != nil {
				return err
			}
			if existing := activeByType[kt]; existing == nil || a.Created.After(existing.Created) {
				activeByType[kt] = a
			}
		}

		for _, pair := range sortedSelectors {
			sel := pair[0].(string)
			created := pair[1].(time.Time)
			kt, err := m.tree.GetKeyType(domainName, sel)
			if err != nil {
				return err
			}
			revoked, err := m.tree.GetRevokeState(domainName, sel)
			if err != nil {
				return err
			}
			if revoked == types.RevokeEnabled {
				continue
			}
			act := activeByType[kt]
			if act == nil {
				continue
			}
			if sel == act.SelectorName {
				continue
			}
			if created.After(act.Created) {
				if err := m.CmdActive(sel, domainName); err != nil {
					return err
				}
				delete(activeByType, kt)
			}
		}
	}
	return nil
}

func (m *Manager) CmdAddNew() error {
	domains, err := m.tree.GetDomainNames()
	if err != nil {
		return err
	}
	for _, domainName := range domains {
		sortedSelectors, err := m.tree.GetSortedCreatedByDomainName(domainName)
		if err != nil {
			return err
		}
		var selectorRSA, selectorED string
		for _, pair := range sortedSelectors {
			sel := pair[0].(string)
			revoked, err := m.tree.GetRevokeState(domainName, sel)
			if err != nil {
				return err
			}
			if revoked == types.RevokeEnabled {
				continue
			}
			kt, err := m.tree.GetKeyType(domainName, sel)
			if err != nil {
				return err
			}
			if selectorRSA == "" && kt == types.DKIMKeyTypeRSA {
				selectorRSA = sel
			}
			if selectorED == "" && kt == types.DKIMKeyTypeED25519 {
				selectorED = sel
			}
			if selectorRSA != "" && selectorED != "" {
				break
			}
		}
		if selectorRSA != "" {
			expired, err := m.expireAfter(domainName, selectorRSA)
			if err != nil {
				return err
			}
			if expired {
				if err := m.CmdCreate(domainName, types.DKIMKeyTypeRSA); err != nil {
					return err
				}
			}
		}
		if selectorED != "" {
			expired, err := m.expireAfter(domainName, selectorED)
			if err != nil {
				return err
			}
			if expired {
				if err := m.CmdCreate(domainName, types.DKIMKeyTypeED25519); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *Manager) CmdPrintDNS() error {
	type target struct {
		domain   string
		selector string
	}
	targets := make([]target, 0)
	seen := map[string]struct{}{}
	appendTarget := func(domainName, selectorName string) {
		key := strings.ToLower(domainName) + "\x00" + selectorName
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, target{domain: domainName, selector: selectorName})
	}

	for _, selectorName := range m.opts.Selectors {
		sel, resolvedDomain, err := m.resolveSelector(selectorName, "", m.opts.Domains)
		if err != nil {
			return err
		}
		if len(m.opts.Domains) == 0 {
			sel, err = m.tree.GetSelector(selectorName)
			if err != nil {
				return err
			}
			if sel != nil {
				resolvedDomain = sel.DomainName
			}
		}
		if sel == nil {
			continue
		}
		appendTarget(resolvedDomain, selectorName)
	}
	for _, dName := range m.opts.Domains {
		selectors, err := m.tree.GetSelectorsByDomainName(dName)
		if err != nil {
			return err
		}
		if len(selectors) == 0 {
			if !m.opts.AcceptAnyDomain {
				return fmt.Errorf("domain %q does not exist", dName)
			}
			fmt.Printf("; Info: domain %q does not exist\n", dName)
			continue
		}
		for selectorName := range selectors {
			appendTarget(dName, selectorName)
		}
	}

	for _, target := range targets {
		kt, err := m.tree.GetKeyType(target.domain, target.selector)
		if err != nil {
			return err
		}
		if kt == types.DKIMKeyTypeUnknown {
			continue
		}
		domain, err := m.tree.GetDomainByDomainName(target.domain)
		if err != nil {
			return err
		}
		key, err := m.tree.GetKey(target.domain, target.selector)
		if err != nil {
			return err
		}
		rev, err := m.tree.GetRevokeState(target.domain, target.selector)
		if err != nil {
			return err
		}
		dk := dkim.NewKeys()
		publicKey := ""
		if rev == types.RevokeDisabled {
			switch kt {
			case types.DKIMKeyTypeRSA:
				if err := dk.GeneratePublicRSA(key); err != nil {
					return err
				}
				publicKey = dk.RSAPublicKey()
			case types.DKIMKeyTypeED25519:
				if err := dk.GeneratePublicED25519(key); err != nil {
					return err
				}
				publicKey = dk.ED25519PublicKey()
			}
		}

		zoneDomain := target.domain
		if domain != nil && domain.DestinationIndicator != "" {
			zone, subdomain, err := m.cnameTarget(domain)
			if err != nil {
				return err
			}
			zoneDomain = subdomain + "." + zone
		}
		serviceType := ""
		if domain != nil {
			serviceType = domain.ServiceType
		}
		content, err := dkimTXTContent(kt, serviceType, publicKey)
		if err != nil {
			return err
		}
		fmt.Printf("%s._domainkey.%s. IN TXT %s\n", target.selector, zoneDomain, dnsupdate.Make254(content))
	}
	return nil
}

func (m *Manager) CmdAddMissing() error {
	countInitial := m.opts.MaxInitial > 0
	counter := 0

	emptyDomains, err := m.tree.GetDomainNamesWithEmptySelectors()
	if err != nil {
		return err
	}
	for _, domainName := range emptyDomains {
		if countInitial && counter == m.opts.MaxInitial {
			return nil
		}
		if err := m.CmdCreate(domainName, types.DKIMKeyTypeUnknown); err != nil {
			return err
		}
		counter++
	}

	domains, err := m.tree.GetDomainNames()
	if err != nil {
		return err
	}
	wantRSA := m.runtime.KeyType == types.DKIMKeyTypeRSA || m.runtime.KeyType == types.DKIMKeyTypeBoth
	wantED := m.runtime.KeyType == types.DKIMKeyTypeED25519 || m.runtime.KeyType == types.DKIMKeyTypeBoth

	for _, domainName := range domains {
		selectors, err := m.tree.GetSelectorsByDomainName(domainName)
		if err != nil {
			return err
		}
		haveRSA := false
		haveED := false
		for name := range selectors {
			revoked, err := m.tree.GetRevokeState(domainName, name)
			if err != nil {
				return err
			}
			if revoked == types.RevokeEnabled {
				continue
			}
			kt, err := m.tree.GetKeyType(domainName, name)
			if err != nil {
				return err
			}
			if kt == types.DKIMKeyTypeRSA {
				haveRSA = true
			}
			if kt == types.DKIMKeyTypeED25519 {
				haveED = true
			}
		}
		if wantRSA && !haveRSA {
			if err := m.CmdCreate(domainName, types.DKIMKeyTypeRSA); err != nil {
				return err
			}
		}
		if wantED && !haveED {
			if err := m.CmdCreate(domainName, types.DKIMKeyTypeED25519); err != nil {
				return err
			}
		}
		counter++
		if countInitial && counter == m.opts.MaxInitial {
			return nil
		}
	}

	return nil
}

func (m *Manager) CmdAuto() error {
	if err := m.preflightMutationDomains(); err != nil {
		return err
	}

	m.verbosef("running add-new")
	if err := m.CmdAddNew(); err != nil {
		return err
	}
	m.verbosef("running add-missing")
	if err := m.CmdAddMissing(); err != nil {
		return err
	}
	m.verbosef("running rotate")
	if err := m.CmdRotate(); err != nil {
		return err
	}

	keyTypes := m.keyTypesForRuntime()
	domains, err := m.tree.GetDomainNames()
	if err != nil {
		return err
	}

	for _, domainName := range domains {
		domain, err := m.tree.GetDomainByDomainName(domainName)
		if err != nil {
			return err
		}
		destination := ""
		if domain != nil {
			destination = domain.DestinationIndicator
		}
		active, err := m.tree.GetActiveSelectorsByDomainName(domainName)
		if err != nil {
			return err
		}
		var activeRSA, activeED *ldapstore.Selector
		for _, a := range active {
			kt, err := m.tree.GetKeyType(domainName, a.SelectorName)
			if err != nil {
				return err
			}
			if kt == types.DKIMKeyTypeRSA && (activeRSA == nil || a.Created.After(activeRSA.Created)) {
				activeRSA = a
			}
			if kt == types.DKIMKeyTypeED25519 && (activeED == nil || a.Created.After(activeED.Created)) {
				activeED = a
			}
		}

		sortedSelectors, err := m.tree.GetSortedCreatedByDomainName(domainName)
		if err != nil {
			return err
		}
		for _, pair := range sortedSelectors {
			sel := pair[0].(string)
			created := pair[1].(time.Time)
			kt, err := m.tree.GetKeyType(domainName, sel)
			if err != nil {
				return err
			}
			rev, err := m.tree.GetRevokeState(domainName, sel)
			if err != nil {
				return err
			}

			if rev == types.RevokeDisabled && kt == types.DKIMKeyTypeRSA {
				if destination == "" && m.containsType(keyTypes, kt) {
					if activeRSA != nil {
						if sel != activeRSA.SelectorName && created.Before(activeRSA.Created) {
							if err := m.CmdDelete(domainName, sel, false); err != nil {
								return err
							}
						}
					} else {
						if err := m.CmdActive(sel, domainName); err != nil {
							return err
						}
						candidate, lookupErr := m.tree.GetSelectorByDomainName(domainName, sel)
						err = lookupErr
						if err != nil {
							return err
						}
						if candidate != nil && candidate.State == types.DKIMEnabled {
							activeRSA = candidate
						}
					}
				}
			}

			if rev == types.RevokeDisabled && kt == types.DKIMKeyTypeED25519 {
				if destination == "" && m.containsType(keyTypes, kt) {
					if activeED != nil {
						if sel != activeED.SelectorName && created.Before(activeED.Created) {
							if err := m.CmdDelete(domainName, sel, false); err != nil {
								return err
							}
						}
					} else {
						if err := m.CmdActive(sel, domainName); err != nil {
							return err
						}
						candidate, lookupErr := m.tree.GetSelectorByDomainName(domainName, sel)
						err = lookupErr
						if err != nil {
							return err
						}
						if candidate != nil && candidate.State == types.DKIMEnabled {
							activeED = candidate
						}
					}
				}
			}

			if rev == types.RevokeEnabled && destination == "" {
				if err := m.CmdDelete(domainName, sel, false); err != nil {
					return err
				}
			}
		}

		if destination != "" {
			if err := m.CmdReorder(domainName); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) preflightMutationDomains() error {
	domains, err := m.tree.GetDomainNames()
	if err != nil {
		return err
	}
	for _, domainName := range domains {
		domain, err := m.tree.GetDomainByDomainName(domainName)
		if err != nil {
			return err
		}
		if domain == nil {
			return fmt.Errorf("domain %q disappeared during mutation preflight", domainName)
		}
		if err := m.validateAutoDomainForMutation(domainName, domain); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) validateDomainForMutation(domainName string, domain *ldapstore.Domain) error {
	if err := validateServiceType(domain.ServiceType); err != nil {
		return fmt.Errorf("domain %q service type: %w", domainName, err)
	}
	if strings.TrimSpace(domain.DestinationIndicator) == "" {
		return nil
	}
	if _, _, err := m.cnameTarget(domain); err != nil {
		return fmt.Errorf("domain %q CNAME target: %w", domainName, err)
	}
	return nil
}

func (m *Manager) validateAutoDomainForMutation(domainName string, domain *ldapstore.Domain) error {
	if err := m.validateDomainForMutation(domainName, domain); err != nil {
		return err
	}
	if strings.TrimSpace(domain.DestinationIndicator) != "" && !m.opts.UpdateDNS && !m.opts.DryRun {
		return fmt.Errorf("domain %q uses CNAME slots; --auto requires --update-dns to reconcile them before LDAP changes", domainName)
	}
	return nil
}

func (m *Manager) CmdReorder(domainName string) error {
	keyTypes := m.keyTypesForRuntime()
	domain, err := m.tree.GetDomainByDomainName(domainName)
	if err != nil {
		return err
	}
	if domain == nil || domain.DestinationIndicator == "" {
		return nil
	}
	zone, subdomain, err := m.cnameTarget(domain)
	if err != nil {
		return err
	}

	sortedSelectors, err := m.tree.GetSortedCreatedByDomainName(domainName)
	if err != nil {
		return err
	}
	rsaSelectors := []string{}
	edSelectors := []string{}
	for _, pair := range sortedSelectors {
		sel := pair[0].(string)
		kt, err := m.tree.GetKeyType(domainName, sel)
		if err != nil {
			return err
		}
		if kt == types.DKIMKeyTypeRSA && m.containsType(keyTypes, kt) {
			rsaSelectors = append(rsaSelectors, sel)
		}
		if kt == types.DKIMKeyTypeED25519 && m.containsType(keyTypes, kt) {
			edSelectors = append(edSelectors, sel)
		}
	}

	if m.containsType(keyTypes, types.DKIMKeyTypeRSA) {
		if err := m.reorderByType(domainName, zone, subdomain, rsaSelectors, types.DKIMKeyTypeRSA, m.runtime.CNAMESelectorRSAPrefix); err != nil {
			return err
		}
	}
	if m.containsType(keyTypes, types.DKIMKeyTypeED25519) {
		if err := m.reorderByType(domainName, zone, subdomain, edSelectors, types.DKIMKeyTypeED25519, m.runtime.CNAMESelectorED25519Prefix); err != nil {
			return err
		}
	}
	return nil
}

type cnameSlotPlan struct {
	source   string
	target   string
	selector *ldapstore.Selector
	content  string
}

type cnameRenameStep struct {
	from string
	to   string
}

func (m *Manager) reorderByType(domainName, zone, subdomain string, selectors []string, keyType types.DKIMKeyType, prefix string) error {
	if !m.containsType(m.keyTypesForRuntime(), keyType) {
		return nil
	}
	domain, err := m.tree.GetDomainByDomainName(domainName)
	if err != nil {
		return err
	}
	if domain == nil {
		return fmt.Errorf("domain %q does not exist", domainName)
	}
	for slot := 1; slot <= 3; slot++ {
		if err := selector.ValidateRecordName(fmt.Sprintf("%s%d", prefix, slot), domainName); err != nil {
			return fmt.Errorf("invalid CNAME selector prefix %q: %w", prefix, err)
		}
	}

	for _, selectorName := range selectors[minimum(3, len(selectors)):] {
		sel := domain.Selectors[selectorName]
		if sel != nil && sel.State == types.DKIMEnabled {
			return fmt.Errorf("refusing to prune active CNAME selector %q for domain %q", selectorName, domainName)
		}
	}

	plans := make([]cnameSlotPlan, 0, minimum(3, len(selectors)))
	for index, selectorName := range selectors[:minimum(3, len(selectors))] {
		sel := domain.Selectors[selectorName]
		if sel == nil {
			return fmt.Errorf("selector %q disappeared from domain %q", selectorName, domainName)
		}
		if index == 2 && sel.State == types.DKIMEnabled {
			return fmt.Errorf("refusing to tombstone active CNAME selector %q for domain %q", selectorName, domainName)
		}
		target := fmt.Sprintf("%s%d", prefix, index+1)
		content := ""
		if index == 2 {
			content, err = dkimTXTContent(keyType, "", "")
		} else {
			publicKey, publicErr := m.publicFromSelector(domainName, selectorName, keyType)
			if publicErr != nil {
				return publicErr
			}
			content, err = dkimTXTContent(keyType, "", publicKey)
		}
		if err != nil {
			return err
		}
		plans = append(plans, cnameSlotPlan{source: selectorName, target: target, selector: sel, content: content})
	}

	renameSteps, err := planCNAMERenames(plans, domain.Selectors)
	if err != nil {
		return err
	}
	if len(renameSteps) > 0 && !m.opts.UpdateDNS && !m.opts.DryRun {
		return errors.New("CNAME selector renames require --update-dns to preserve selector/key consistency")
	}

	for _, selectorName := range selectors[minimum(3, len(selectors)):] {
		if err := m.CmdDelete(domainName, selectorName, true); err != nil {
			return err
		}
	}

	contentByTarget := make(map[string]string, len(plans))
	for _, plan := range plans {
		contentByTarget[plan.target] = plan.content
	}
	for _, step := range renameSteps {
		if content, ok := contentByTarget[step.to]; ok && m.opts.UpdateDNS {
			if err := m.changeDNSDKIMKey(zone, step.to, content, subdomain); err != nil {
				return err
			}
		}
		if err := m.renameCNAMESelector(domainName, step.from, step.to); err != nil {
			return err
		}
	}

	for index := 0; index < 2; index++ {
		target := fmt.Sprintf("%s%d", prefix, index+1)
		content, present := contentByTarget[target]
		if !m.opts.UpdateDNS {
			continue
		}
		if present {
			if err := m.changeDNSDKIMKey(zone, target, content, subdomain); err != nil {
				return err
			}
		} else if err := m.removeDNSDKIMKey(zone, target, subdomain); err != nil {
			return err
		}
	}
	if len(plans) > 0 {
		if m.opts.UpdateDNS {
			if err := m.activateCNAMESelector(domainName, plans[0].target, keyType); err != nil {
				return err
			}
		} else if err := m.CmdActive(plans[0].target, domainName); err != nil {
			return err
		}
	}
	tombstone, err := dkimTXTContent(keyType, "", "")
	if err != nil {
		return err
	}
	if m.opts.UpdateDNS {
		if err := m.changeDNSDKIMKey(zone, fmt.Sprintf("%s3", prefix), tombstone, subdomain); err != nil {
			return err
		}
	}

	staticNames := map[string]struct{}{
		fmt.Sprintf("%s1", prefix): {},
		fmt.Sprintf("%s2", prefix): {},
		fmt.Sprintf("%s3", prefix): {},
	}
	if m.opts.UpdateDNS {
		for _, plan := range plans {
			if plan.source == plan.target {
				continue
			}
			if _, keep := staticNames[plan.source]; keep {
				continue
			}
			if err := m.removeDNSDKIMKey(zone, plan.source, subdomain); err != nil {
				return err
			}
		}
	}

	if len(plans) == 3 {
		if err := m.CmdDelete(domainName, plans[2].target, false); err != nil {
			return err
		}
	}
	return nil
}

func planCNAMERenames(plans []cnameSlotPlan, allSelectors map[string]*ldapstore.Selector) ([]cnameRenameStep, error) {
	type move struct {
		current  string
		target   string
		selector *ldapstore.Selector
	}
	moves := make([]*move, 0, len(plans))
	occupied := make(map[string]*ldapstore.Selector, len(plans))
	used := make(map[string]struct{}, len(allSelectors))
	for name := range allSelectors {
		used[name] = struct{}{}
	}
	for _, plan := range plans {
		occupied[plan.source] = plan.selector
		if plan.source != plan.target {
			moves = append(moves, &move{current: plan.source, target: plan.target, selector: plan.selector})
		}
	}
	steps := make([]cnameRenameStep, 0, len(moves)+1)
	for len(moves) > 0 {
		progress := false
		for index, candidate := range moves {
			if _, blocked := occupied[candidate.target]; blocked {
				continue
			}
			steps = append(steps, cnameRenameStep{from: candidate.current, to: candidate.target})
			delete(occupied, candidate.current)
			occupied[candidate.target] = candidate.selector
			moves = append(moves[:index], moves[index+1:]...)
			progress = true
			break
		}
		if progress {
			continue
		}
		cycleIndex := -1
		for index, candidate := range moves {
			if candidate.selector.State != types.DKIMEnabled {
				cycleIndex = index
				break
			}
		}
		if cycleIndex < 0 {
			return nil, errors.New("cannot safely reconcile a CNAME selector rename cycle containing only active selectors")
		}
		candidate := moves[cycleIndex]
		temporary := temporarySelectorName(candidate.selector.LDAPDN, used)
		steps = append(steps, cnameRenameStep{from: candidate.current, to: temporary})
		delete(occupied, candidate.current)
		occupied[temporary] = candidate.selector
		used[temporary] = struct{}{}
		candidate.current = temporary
	}
	return steps, nil
}

func temporarySelectorName(ldapDN string, used map[string]struct{}) string {
	digest := sha256.Sum256([]byte(ldapDN))
	for length := 6; length <= 27; length++ {
		candidate := fmt.Sprintf("dkimtmp-%x", digest[:length])
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	return fmt.Sprintf("dkimtmp-%x", digest[:27])
}

func (m *Manager) renameCNAMESelector(domainName, oldName, newName string) error {
	domain, err := m.tree.GetDomainByDomainName(domainName)
	if err != nil {
		return err
	}
	sel := domain.Selectors[oldName]
	if sel == nil {
		return fmt.Errorf("selector %q does not exist for domain %q", oldName, domainName)
	}
	if err := m.renameSelectorDN(sel.LDAPDN, newName); err != nil {
		return err
	}
	if m.opts.DryRun {
		delete(domain.Selectors, oldName)
		sel.SelectorName = newName
		domain.Selectors[newName] = sel
		return nil
	}
	return m.tree.ReloadSelectorsByDomainName(domainName)
}

func (m *Manager) activateCNAMESelector(domainName, selectorName string, keyType types.DKIMKeyType) error {
	sel, err := m.tree.GetSelectorByDomainName(domainName, selectorName)
	if err != nil {
		return err
	}
	if sel == nil {
		return fmt.Errorf("selector %q does not exist for domain %q", selectorName, domainName)
	}
	active, err := m.tree.GetActiveSelectorsByDomainName(domainName)
	if err != nil {
		return err
	}
	if sel.State != types.DKIMEnabled {
		if err := m.setActive(sel.LDAPDN, true); err != nil {
			return err
		}
		if m.opts.DryRun {
			sel.State = types.DKIMEnabled
		}
	}
	for _, current := range active {
		if current.SelectorName == selectorName {
			continue
		}
		currentType, err := m.tree.GetKeyType(domainName, current.SelectorName)
		if err != nil {
			return err
		}
		if currentType != keyType {
			continue
		}
		if err := m.setActive(current.LDAPDN, false); err != nil {
			return err
		}
		if m.opts.DryRun {
			current.State = types.DKIMDisabled
		}
	}
	if m.opts.DryRun {
		return nil
	}
	return m.tree.ReloadSelectorsByDomainName(domainName)
}

func minimum(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (m *Manager) expireAfter(domainName, selectorName string) (bool, error) {
	sel, err := m.tree.GetSelectorByDomainName(domainName, selectorName)
	if err != nil {
		return false, err
	}
	if sel == nil || sel.SelectorName == "" {
		return false, fmt.Errorf("selector %q does not exist for domain %q", selectorName, domainName)
	}
	return time.Since(sel.Created) >= time.Duration(m.runtime.ExpireAfter)*24*time.Hour, nil
}

func (m *Manager) resolveNewSelectorName(domainName string) (string, error) {
	if len(m.opts.Selectors) > 0 {
		sel := m.opts.Selectors[0]
		if err := selector.ValidateRecordName(sel, domainName); err != nil {
			return "", err
		}
		return sel, nil
	}
	if strings.TrimSpace(m.runtime.SelectorFormat) == "" {
		return "", errors.New("no selectorformat configured and no --selectorname provided")
	}
	b := selector.Builder{Format: m.runtime.SelectorFormat}
	s, err := b.Parse()
	if err != nil {
		return "", err
	}
	if err := selector.ValidateRecordName(s, domainName); err != nil {
		return "", err
	}
	return s, nil
}

func (m *Manager) resolveSelector(selectorName, domainName string, fallbackDomains []string) (*ldapstore.Selector, string, error) {
	if domainName != "" {
		sel, err := m.tree.GetSelectorByDomainName(domainName, selectorName)
		return sel, domainName, err
	}
	var found *ldapstore.Selector
	foundDomain := ""
	for _, d := range fallbackDomains {
		sel, err := m.tree.GetSelectorByDomainName(d, selectorName)
		if err != nil {
			return nil, "", err
		}
		if sel != nil && sel.SelectorName != "" {
			if found != nil && foundDomain != d {
				return nil, "", fmt.Errorf("selector %q is ambiguous across domains %q and %q; specify exactly one domain", selectorName, foundDomain, d)
			}
			found = sel
			foundDomain = d
		}
	}
	return found, foundDomain, nil
}

func (m *Manager) keyTypesForCreate(explicit types.DKIMKeyType) []types.DKIMKeyType {
	if explicit != types.DKIMKeyTypeUnknown {
		switch explicit {
		case types.DKIMKeyTypeBoth:
			return []types.DKIMKeyType{types.DKIMKeyTypeRSA, types.DKIMKeyTypeED25519}
		case types.DKIMKeyTypeRSA, types.DKIMKeyTypeED25519:
			return []types.DKIMKeyType{explicit}
		}
	}
	switch m.runtime.KeyType {
	case types.DKIMKeyTypeBoth:
		return []types.DKIMKeyType{types.DKIMKeyTypeRSA, types.DKIMKeyTypeED25519}
	case types.DKIMKeyTypeRSA:
		return []types.DKIMKeyType{types.DKIMKeyTypeRSA}
	case types.DKIMKeyTypeED25519:
		return []types.DKIMKeyType{types.DKIMKeyTypeED25519}
	default:
		return []types.DKIMKeyType{types.DKIMKeyTypeRSA, types.DKIMKeyTypeED25519}
	}
}

func (m *Manager) keyTypesForRuntime() []types.DKIMKeyType {
	return m.keyTypesForCreate(types.DKIMKeyTypeUnknown)
}

func (m *Manager) containsType(arr []types.DKIMKeyType, typ types.DKIMKeyType) bool {
	for _, t := range arr {
		if t == typ {
			return true
		}
	}
	return false
}

func (m *Manager) publicFromSelector(domainName, selectorName string, keyType types.DKIMKeyType) (string, error) {
	key, err := m.tree.GetKey(domainName, selectorName)
	if err != nil {
		return "", err
	}
	dk := dkim.NewKeys()
	if keyType == types.DKIMKeyTypeRSA {
		if err := dk.GeneratePublicRSA(key); err != nil {
			return "", err
		}
		return dk.RSAPublicKey(), nil
	}
	if err := dk.GeneratePublicED25519(key); err != nil {
		return "", err
	}
	return dk.ED25519PublicKey(), nil
}

func (m *Manager) inputDomainsOrAll() ([]string, error) {
	if len(m.opts.Domains) > 0 {
		return append([]string{}, m.opts.Domains...), nil
	}
	return m.tree.GetDomainNames()
}

func (m *Manager) cnameTarget(domain *ldapstore.Domain) (string, string, error) {
	if domain == nil || strings.TrimSpace(domain.DestinationIndicator) == "" {
		return "", "", errors.New("CNAME target requires a destinationIndicator")
	}
	if err := validateLDHDomain(domain.DomainName); err != nil {
		return "", "", fmt.Errorf("CNAME source domain %q: %w", domain.DomainName, err)
	}
	zone := strings.Trim(strings.TrimSpace(domain.DestinationIndicator), ".")
	if err := validateLDHDomain(zone); err != nil {
		return "", "", fmt.Errorf("CNAME destination zone %q: %w", zone, err)
	}
	configured := strings.TrimSpace(m.cfg.DNS.CNAMEs)
	allowed := false
	for _, candidate := range strings.FieldsFunc(configured, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if strings.EqualFold(strings.Trim(candidate, "."), zone) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", "", fmt.Errorf("destinationIndicator %q is not allowed by dns.cnames", zone)
	}
	return zone, strings.ReplaceAll(strings.Trim(domain.DomainName, "."), ".", "_"), nil
}

func validateLDHDomain(domain string) error {
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" || len(domain) > 253 {
		return errors.New("must be a non-empty DNS name of at most 253 bytes")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS label %q", label)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("DNS label %q contains non-LDH character %q", label, r)
		}
	}
	return nil
}

func validateServiceType(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" {
		return nil
	}
	for _, token := range strings.Split(value, ":") {
		if token == "" {
			return errors.New("must be '*' or a colon-separated list of service names")
		}
		for _, r := range token {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("contains invalid character %q", r)
		}
	}
	return nil
}

func dkimTXTContent(keyType types.DKIMKeyType, serviceType, publicKey string) (string, error) {
	if keyType != types.DKIMKeyTypeRSA && keyType != types.DKIMKeyTypeED25519 {
		return "", fmt.Errorf("unsupported DKIM key type %q", keyType.String())
	}
	if err := validateServiceType(serviceType); err != nil {
		return "", err
	}
	fields := []string{"v=DKIM1", "k=" + keyType.String(), "h=sha256"}
	if strings.TrimSpace(serviceType) != "" {
		fields = append(fields, "s="+strings.TrimSpace(serviceType))
	}
	fields = append(fields, "p="+strings.TrimSpace(publicKey))
	return strings.Join(fields, "; "), nil
}

func (m *Manager) confirm(question string) (bool, error) {
	if m.writeAuthorized {
		return true, nil
	}
	if m.opts.DryRun {
		m.dryRunf("assuming yes for confirmation: %s", question)
		return true, nil
	}
	if !m.opts.Interactive {
		if m.opts.Yes {
			return true, nil
		}
		return false, errConfirmationRequired
	}
	fmt.Printf("%s (y/N): ", question)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func (m *Manager) isMutatingCommand() bool {
	return m.opts.Create || m.opts.Delete || m.opts.Active || m.opts.Rotate || m.opts.AddNew || m.opts.AddMissing || m.opts.Auto
}

func (m *Manager) authorizeWrites() error {
	ok, err := m.confirm("Authorize this run to change LDAP and, when requested, DNS?")
	if err != nil {
		return err
	}
	if !ok {
		return errConfirmationRequired
	}
	m.writeAuthorized = true
	return nil
}

func (m *Manager) storeDKIMKey(dn, pemKey string, keyType types.DKIMKeyType, domain, signingTableDomain string, identity *string) error {
	if m.opts.DryRun {
		m.dryRunf("would add LDAP DKIM key dn=%s domain=%s signing-domain=%s keytype=%s", dn, domain, signingTableDomain, keyType.String())
		return nil
	}
	return m.ldap.StoreDKIMKey(dn, pemKey, keyType, domain, signingTableDomain, identity)
}

func (m *Manager) deleteDKIMKey(dn string) error {
	if m.opts.DryRun {
		m.dryRunf("would delete LDAP DKIM key dn=%s", dn)
		return nil
	}
	return m.ldap.DeleteDKIMKey(dn)
}

func (m *Manager) revokeDKIMKey(dn string) error {
	if m.opts.DryRun {
		m.dryRunf("would revoke LDAP DKIM key dn=%s", dn)
		return nil
	}
	return m.ldap.RevokeDKIMKey(dn)
}

func (m *Manager) setActive(dn string, active bool) error {
	if m.opts.DryRun {
		m.dryRunf("would set LDAP DKIM active=%t dn=%s", active, dn)
		return nil
	}
	return m.ldap.SetActive(dn, active)
}

func (m *Manager) renameSelectorDN(dn, newSelectorName string) error {
	if m.opts.DryRun {
		m.dryRunf("would rename LDAP selector dn=%s new-selector=%s", dn, newSelectorName)
		return nil
	}
	return m.ldap.RenameSelectorDN(dn, newSelectorName)
}

func (m *Manager) addDNSDKIMKey(zone, selectorName, content, subdomain string) error {
	if m.opts.DryRun {
		m.dryRunf("would add DNS DKIM selector=%s zone=%s subdomain=%s", selectorName, zone, subdomain)
		return nil
	}
	return m.dns.AddDKIMKey(zone, selectorName, content, subdomain)
}

func (m *Manager) removeDNSDKIMKey(zone, selectorName, subdomain string) error {
	if m.opts.DryRun {
		m.dryRunf("would remove DNS DKIM selector=%s zone=%s subdomain=%s", selectorName, zone, subdomain)
		return nil
	}
	return m.dns.RemoveDKIMKey(zone, selectorName, subdomain)
}

func (m *Manager) changeDNSDKIMKey(zone, selectorName, content, subdomain string) error {
	if m.opts.DryRun {
		m.dryRunf("would change DNS DKIM selector=%s zone=%s subdomain=%s", selectorName, zone, subdomain)
		return nil
	}
	return m.dns.ChangeDKIMKey(zone, selectorName, content, subdomain)
}

func (m *Manager) dryRunf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "DRY-RUN: "+format+"\n", args...)
}

func (m *Manager) verbosef(format string, args ...any) {
	if m.opts.Verbose {
		fmt.Printf(format+"\n", args...)
	}
}

func (m *Manager) warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "WARN: "+format+"\n", args...)
}

func privateKeyByType(dk *dkim.Keys, keyType types.DKIMKeyType) string {
	if keyType == types.DKIMKeyTypeRSA {
		return dk.RSAPrivateKey()
	}
	return dk.ED25519PrivateKey()
}

func publicKeyByType(dk *dkim.Keys, keyType types.DKIMKeyType) string {
	if keyType == types.DKIMKeyTypeRSA {
		return dk.RSAPublicKey()
	}
	return dk.ED25519PublicKey()
}
