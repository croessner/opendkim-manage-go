package ldapstore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
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

	return URI{
		Scheme:             u.Scheme,
		HostPort:           u.Host,
		BaseDN:             strings.TrimPrefix(u.Path, "/"),
		Scope:              scope,
		CustomSearchFilter: customFilter,
	}, nil
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
