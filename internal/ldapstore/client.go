package ldapstore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type URI struct {
	Scheme             string
	HostPort           string
	BaseDN             string
	Scope              int
	CustomSearchFilter string
}

type Client struct {
	cfg    *config.Config
	scheme types.Scheme
	uri    URI
	conn   *ldap.Conn
}

// RequestExecutor exposes the exact LDAP operations needed by immutable
// generation repositories without exposing the underlying connection.
type RequestExecutor interface {
	BaseDN() string
	SearchRequest(*ldap.SearchRequest) (*ldap.SearchResult, error)
	AddRequest(*ldap.AddRequest) error
	ModifyRequest(*ldap.ModifyRequest) (*ldap.ModifyResult, error)
}

var _ RequestExecutor = (*Client)(nil)

var attributeDescriptionPattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*$`)

func NewClient(cfg *config.Config) (*Client, error) {
	u, err := ParseLDAPURI(cfg.LDAP.URI)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, scheme: cfg.Scheme, uri: u}, nil
}

func ParseLDAPURI(raw string) (URI, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return URI{}, fmt.Errorf("invalid ldap uri: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return URI{}, fmt.Errorf("unsupported ldap uri scheme: %s", u.Scheme)
	}
	if strings.TrimSpace(u.Host) == "" {
		return URI{}, fmt.Errorf("ldap uri host is empty")
	}

	scope := ldap.ScopeWholeSubtree
	customFilter := ""
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "?")
		if len(parts) >= 2 {
			switch strings.ToLower(parts[1]) {
			case "base":
				scope = ldap.ScopeBaseObject
			case "one":
				scope = ldap.ScopeSingleLevel
			case "sub", "":
				scope = ldap.ScopeWholeSubtree
			default:
				return URI{}, fmt.Errorf("unsupported ldap scope: %s", parts[1])
			}
		}
		if len(parts) >= 3 {
			customFilter = strings.TrimSpace(parts[2])
		}
	}

	baseDN := strings.TrimPrefix(u.Path, "/")
	if _, err := ldap.ParseDN(baseDN); err != nil {
		return URI{}, fmt.Errorf("invalid ldap uri base dn")
	}

	return URI{
		Scheme:             u.Scheme,
		HostPort:           u.Host,
		BaseDN:             baseDN,
		Scope:              scope,
		CustomSearchFilter: customFilter,
	}, nil
}

// BaseDN returns the validated dataset base parsed from the configured LDAP
// URI so repositories never derive a write base from request input.
func (c *Client) BaseDN() string {
	return c.uri.BaseDN
}

func (c *Client) CustomSearchFilter() string {
	return c.uri.CustomSearchFilter
}

func (c *Client) EnsureConnected() error {
	if c.conn != nil {
		return nil
	}

	tlsCfg, err := c.buildTLSConfig()
	if err != nil {
		return err
	}

	address := c.uri.HostPort
	if _, _, errSplit := net.SplitHostPort(address); errSplit != nil {
		if c.uri.Scheme == "ldaps" {
			address = net.JoinHostPort(address, "636")
		} else {
			address = net.JoinHostPort(address, "389")
		}
	}

	dialURL := c.uri.Scheme + "://" + address
	dialOptions := make([]ldap.DialOpt, 0, 1)
	if c.uri.Scheme == "ldaps" {
		dialOptions = append(dialOptions, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(dialURL, dialOptions...)
	if err != nil {
		return fmt.Errorf("ldap dial failed: %w", err)
	}
	conn.SetTimeout(60 * time.Second)

	if c.cfg.LDAP.UseStartTLS && c.uri.Scheme != "ldaps" {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return errors.Join(fmt.Errorf("ldap starttls failed: %w", err), closeLDAPConnection(conn))
		}
	}

	if err := c.bind(conn); err != nil {
		return errors.Join(err, closeLDAPConnection(conn))
	}
	c.conn = conn
	return nil
}

func (c *Client) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: c.tlsServerName(),
	}

	switch strings.ToLower(strings.TrimSpace(c.cfg.LDAP.ReqCert)) {
	case "never", "allow", "try":
		tlsCfg.InsecureSkipVerify = true
	case "", "demand":
		tlsCfg.InsecureSkipVerify = false
	default:
		return nil, fmt.Errorf("unsupported ldap reqcert: %s", c.cfg.LDAP.ReqCert)
	}

	if strings.TrimSpace(c.cfg.LDAP.CA) != "" {
		caPEM, err := os.ReadFile(c.cfg.LDAP.CA)
		if err != nil {
			return nil, fmt.Errorf("read ldap ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse ldap ca cert")
		}
		tlsCfg.RootCAs = pool
	}

	if strings.TrimSpace(c.cfg.LDAP.Cert) != "" || strings.TrimSpace(c.cfg.LDAP.Key) != "" {
		if strings.TrimSpace(c.cfg.LDAP.Cert) == "" || strings.TrimSpace(c.cfg.LDAP.Key) == "" {
			return nil, fmt.Errorf("both ldap cert and key must be set")
		}
		cert, err := tls.LoadX509KeyPair(c.cfg.LDAP.Cert, c.cfg.LDAP.Key)
		if err != nil {
			return nil, fmt.Errorf("load ldap client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func (c *Client) tlsServerName() string {
	host := c.uri.HostPort
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

func (c *Client) bind(conn *ldap.Conn) error {
	if strings.EqualFold(c.cfg.LDAP.BindMethod, "sasl") {
		mech := strings.ToLower(strings.TrimSpace(c.cfg.LDAP.SASLMech))
		switch mech {
		case "external":
			if err := conn.ExternalBind(); err != nil {
				return fmt.Errorf("ldap sasl external bind failed: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("unsupported sasl mechanism %q; refusing silent simple-bind fallback", c.cfg.LDAP.SASLMech)
		}
	}

	if strings.TrimSpace(c.cfg.LDAP.BindDN) == "" && strings.TrimSpace(c.cfg.LDAP.BindPW) == "" {
		return nil
	}
	if err := conn.Bind(c.cfg.LDAP.BindDN, c.cfg.LDAP.BindPW); err != nil {
		return fmt.Errorf("ldap simple bind failed: %w", err)
	}
	return nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		if err != nil {
			return fmt.Errorf("close LDAP connection: %w", err)
		}
	}
	return nil
}

func closeLDAPConnection(conn *ldap.Conn) error {
	if err := conn.Close(); err != nil {
		return fmt.Errorf("close LDAP connection: %w", err)
	}
	return nil
}

func (c *Client) Search(searchFilter, base string, attrs []string, scope int) ([]*ldap.Entry, error) {
	if len(attrs) == 0 {
		return nil, fmt.Errorf("at least one attribute is required")
	}
	if err := c.EnsureConnected(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(base) == "" {
		base = c.uri.BaseDN
	}
	if scope == 0 {
		scope = c.uri.Scope
	}
	if strings.TrimSpace(searchFilter) == "" {
		searchFilter = "(objectClass=*)"
	}

	req := ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0,
		60,
		false,
		searchFilter,
		attrs,
		nil,
	)
	resp, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", err)
	}
	return resp.Entries, nil
}

// SearchRequest validates and executes one bounded exact-attribute search
// through the client's existing secure connection and bind policy.
func (c *Client) SearchRequest(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if err := c.validateSearchRequest(req); err != nil {
		return nil, err
	}
	if err := c.EnsureConnected(); err != nil {
		return nil, err
	}

	result, err := c.conn.Search(req)
	if err != nil {
		return nil, safeRequestError("search", err)
	}
	return result, nil
}

// AddRequest validates and executes one complete LDAP entry add without
// formatting its DN or potentially secret-bearing values into errors.
func (c *Client) AddRequest(req *ldap.AddRequest) error {
	if err := c.validateAddRequest(req); err != nil {
		return err
	}
	if err := c.EnsureConnected(); err != nil {
		return err
	}

	if err := c.conn.Add(req); err != nil {
		return safeRequestError("add", err)
	}
	return nil
}

// ModifyRequest validates and executes one replacement-only LDAP modify and
// returns response metadata so callers can reject referrals or ambiguity.
func (c *Client) ModifyRequest(req *ldap.ModifyRequest) (*ldap.ModifyResult, error) {
	if err := c.validateModifyRequest(req); err != nil {
		return nil, err
	}
	if err := c.EnsureConnected(); err != nil {
		return nil, err
	}

	result, err := c.conn.ModifyWithResult(req)
	if err != nil {
		return nil, safeRequestError("modify", err)
	}
	return result, nil
}

// validateSearchRequest enforces bounded exact reads inside the configured
// dataset before any connection can be established.
func (c *Client) validateSearchRequest(req *ldap.SearchRequest) error {
	if req == nil {
		return errors.New("ldap search request is nil")
	}
	if err := c.validateRequestDN(req.BaseDN); err != nil {
		return fmt.Errorf("ldap search request base: %w", err)
	}
	if req.Scope != ldap.ScopeBaseObject && req.Scope != ldap.ScopeSingleLevel && req.Scope != ldap.ScopeWholeSubtree {
		return errors.New("ldap search request scope is unsupported")
	}
	if req.DerefAliases != ldap.NeverDerefAliases {
		return errors.New("ldap search request must not dereference aliases")
	}
	if req.SizeLimit <= 0 || !req.EnforceSizeLimit {
		return errors.New("ldap search request requires an enforced positive size limit")
	}
	if req.TimeLimit <= 0 {
		return errors.New("ldap search request requires a positive time limit")
	}
	if req.TypesOnly {
		return errors.New("ldap search request must request attribute values")
	}
	if strings.TrimSpace(req.Filter) == "" {
		return errors.New("ldap search request filter is empty")
	}
	if _, err := ldap.CompileFilter(req.Filter); err != nil {
		return errors.New("ldap search request filter is invalid")
	}
	if err := validateAttributeDescriptions(req.Attributes); err != nil {
		return fmt.Errorf("ldap search request attributes: %w", err)
	}
	if err := validateControls(req.Controls); err != nil {
		return fmt.Errorf("ldap search request controls: %w", err)
	}
	return nil
}

// validateAddRequest rejects incomplete or ambiguous entries before any
// potentially secret-bearing values reach the LDAP connection.
func (c *Client) validateAddRequest(req *ldap.AddRequest) error {
	if req == nil {
		return errors.New("ldap add request is nil")
	}
	if err := c.validateRequestDN(req.DN); err != nil {
		return fmt.Errorf("ldap add request dn: %w", err)
	}
	if len(req.Attributes) == 0 {
		return errors.New("ldap add request requires at least one attribute")
	}

	seen := make(map[string]struct{}, len(req.Attributes))
	for _, attribute := range req.Attributes {
		if err := validateAttributeDescription(attribute.Type); err != nil {
			return fmt.Errorf("ldap add request attribute: %w", err)
		}
		name := strings.ToLower(attribute.Type)
		if _, ok := seen[name]; ok {
			return errors.New("ldap add request contains a duplicate attribute")
		}
		seen[name] = struct{}{}
		if err := validateNonemptyValues(attribute.Vals); err != nil {
			return fmt.Errorf("ldap add request attribute values: %w", err)
		}
	}
	if err := validateControls(req.Controls); err != nil {
		return fmt.Errorf("ldap add request controls: %w", err)
	}
	return nil
}

// validateModifyRequest limits immutable-generation publication to exact
// replacement operations inside the configured dataset.
func (c *Client) validateModifyRequest(req *ldap.ModifyRequest) error {
	if req == nil {
		return errors.New("ldap modify request is nil")
	}
	if err := c.validateRequestDN(req.DN); err != nil {
		return fmt.Errorf("ldap modify request dn: %w", err)
	}
	if len(req.Changes) == 0 {
		return errors.New("ldap modify request requires at least one change")
	}

	seen := make(map[string]struct{}, len(req.Changes))
	for _, change := range req.Changes {
		if change.Operation != ldap.ReplaceAttribute {
			return errors.New("ldap modify request permits replacement changes only")
		}
		if err := validateAttributeDescription(change.Modification.Type); err != nil {
			return fmt.Errorf("ldap modify request attribute: %w", err)
		}
		name := strings.ToLower(change.Modification.Type)
		if _, ok := seen[name]; ok {
			return errors.New("ldap modify request contains a duplicate attribute")
		}
		seen[name] = struct{}{}
		if err := validateNonemptyValues(change.Modification.Vals); err != nil {
			return fmt.Errorf("ldap modify request attribute values: %w", err)
		}
	}
	if err := validateControls(req.Controls); err != nil {
		return fmt.Errorf("ldap modify request controls: %w", err)
	}
	return nil
}

// validateRequestDN requires a syntactically valid target at or below the
// configured LDAP URI base.
func (c *Client) validateRequestDN(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("dn is empty")
	}
	target, err := ldap.ParseDN(raw)
	if err != nil {
		return errors.New("dn is invalid")
	}
	base, err := ldap.ParseDN(c.uri.BaseDN)
	if err != nil || len(base.RDNs) == 0 {
		return errors.New("configured base dn is invalid or empty")
	}
	if !base.Equal(target) && !base.AncestorOf(target) {
		return errors.New("dn is outside the configured base")
	}
	return nil
}

// validateAttributeDescriptions requires a unique list of explicit LDAP
// attribute descriptions and rejects wildcard selectors.
func validateAttributeDescriptions(attributes []string) error {
	if len(attributes) == 0 {
		return errors.New("at least one exact attribute is required")
	}
	seen := make(map[string]struct{}, len(attributes))
	for _, attribute := range attributes {
		if err := validateAttributeDescription(attribute); err != nil {
			return err
		}
		name := strings.ToLower(attribute)
		if _, ok := seen[name]; ok {
			return errors.New("duplicate attribute is not allowed")
		}
		seen[name] = struct{}{}
	}
	return nil
}

// validateAttributeDescription accepts named or numeric LDAP attribute
// descriptions with optional explicit attribute options.
func validateAttributeDescription(attribute string) error {
	if !attributeDescriptionPattern.MatchString(attribute) {
		return errors.New("attribute description is empty, broad, or invalid")
	}
	return nil
}

// validateNonemptyValues prevents incomplete add or replacement operations.
func validateNonemptyValues(values []string) error {
	if len(values) == 0 {
		return errors.New("at least one value is required")
	}
	for _, value := range values {
		if len(value) == 0 {
			return errors.New("empty values are not allowed")
		}
	}
	return nil
}

// validateControls rejects controls that would panic or encode without an OID.
func validateControls(controls []ldap.Control) error {
	for _, control := range controls {
		if control == nil {
			return errors.New("nil control is not allowed")
		}
		value := reflect.ValueOf(control)
		if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) && value.IsNil() {
			return errors.New("nil control is not allowed")
		}
		if strings.TrimSpace(control.GetControlType()) == "" {
			return errors.New("control type is empty")
		}
	}
	return nil
}

// safeRequestError preserves an LDAP result code while discarding server
// diagnostics that could repeat request DNs or secret-bearing values.
func safeRequestError(operation string, err error) error {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		redacted := ldap.NewError(ldapErr.ResultCode, errors.New("request rejected"))
		return fmt.Errorf("ldap %s request failed: %w", operation, redacted)
	}
	return fmt.Errorf("ldap %s request failed", operation)
}

func (c *Client) StoreDKIMKey(dn, pemKey string, keyType types.DKIMKeyType, domain, signingTableDomain string, identity *string) error {
	if err := c.EnsureConnected(); err != nil {
		return err
	}
	oc := []string{"top", c.scheme.DKIM, c.scheme.DomainRelatedObject}
	attrs := map[string][]string{
		"objectClass":             oc,
		c.scheme.DKIMKey:          {strings.TrimSpace(pemKey)},
		c.scheme.DKIMActive:       {"FALSE"},
		c.scheme.AssociatedDomain: {domain},
		c.scheme.DKIMDomain:       {signingTableDomain},
		c.scheme.DKIMKeyType:      {keyType.String()},
	}
	if identity != nil && strings.TrimSpace(*identity) != "" {
		attrs[c.scheme.DKIMIdentity] = []string{*identity}
	}

	req := ldap.NewAddRequest(dn, nil)
	for k, values := range attrs {
		req.Attribute(k, values)
	}
	if err := c.conn.Add(req); err != nil {
		return fmt.Errorf("ldap add failed for %s: %w", dn, err)
	}
	return nil
}

func (c *Client) DeleteDKIMKey(dn string) error {
	if err := c.EnsureConnected(); err != nil {
		return err
	}
	if err := c.conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		return fmt.Errorf("ldap delete failed for %s: %w", dn, err)
	}
	return nil
}

func (c *Client) SetActive(dn string, active bool) error {
	if err := c.EnsureConnected(); err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(dn, nil)
	if active {
		mod.Replace(c.scheme.DKIMActive, []string{"TRUE"})
	} else {
		mod.Replace(c.scheme.DKIMActive, []string{"FALSE"})
	}
	if err := c.conn.Modify(mod); err != nil {
		return fmt.Errorf("ldap modify active failed for %s: %w", dn, err)
	}
	return nil
}

func (c *Client) RevokeDKIMKey(dn string) error {
	if err := c.EnsureConnected(); err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace(c.scheme.DKIMKey, []string{"revoked"})
	if err := c.conn.Modify(mod); err != nil {
		return fmt.Errorf("ldap revoke failed for %s: %w", dn, err)
	}
	return nil
}

func (c *Client) RenameSelectorDN(dn, newSelectorName string) error {
	if err := c.EnsureConnected(); err != nil {
		return err
	}
	newRDN := fmt.Sprintf("%s=%s", c.scheme.DKIMSelector, newSelectorName)
	if err := c.conn.ModifyDN(&ldap.ModifyDNRequest{DN: dn, NewRDN: newRDN, DeleteOldRDN: true}); err != nil {
		return fmt.Errorf("ldap rename failed for %s: %w", dn, err)
	}
	return nil
}
