package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/croessner/opendkim-manage-go/internal/types"
)

const DefaultConfigPath = "/etc/opendkim-manage.yaml"

type GlobalConfig struct {
	DeleteDelay                int      `mapstructure:"delete_delay" yaml:"delete_delay"`
	ExpireAfter                int      `mapstructure:"expire_after" yaml:"expire_after"`
	SelectorFormat             string   `mapstructure:"selectorformat" yaml:"selectorformat"`
	UseDKIMIdentity            bool     `mapstructure:"use_dkim_identity" yaml:"use_dkim_identity"`
	TerminalBackground         string   `mapstructure:"terminal_background" yaml:"terminal_background"`
	KeyType                    string   `mapstructure:"keytype" yaml:"keytype"`
	MaxRevoked                 int      `mapstructure:"max_revoked" yaml:"max_revoked"`
	RevokedRetention           int      `mapstructure:"revoked_retention" yaml:"revoked_retention"`
	CNAMESelectorRSAPrefix     string   `mapstructure:"cname_selector_rsa_prefix" yaml:"cname_selector_rsa_prefix"`
	CNAMESelectorED25519Prefix string   `mapstructure:"cname_selector_ed25519_prefix" yaml:"cname_selector_ed25519_prefix"`
	MultipleSignaturesDomains  []string `mapstructure:"multiple_signatures_domains" yaml:"multiple_signatures_domains"`
}

type LDAPConfig struct {
	URI                  string `mapstructure:"uri" yaml:"uri"`
	BindMethod           string `mapstructure:"bindmethod" yaml:"bindmethod"`
	SASLMech             string `mapstructure:"saslmech" yaml:"saslmech"`
	DomainAttribute      string `mapstructure:"domain" yaml:"domain"`
	UseStartTLS          bool   `mapstructure:"use_starttls" yaml:"use_starttls"`
	ReqCert              string `mapstructure:"reqcert" yaml:"reqcert"`
	Ciphers              string `mapstructure:"ciphers" yaml:"ciphers"`
	Cert                 string `mapstructure:"cert" yaml:"cert"`
	Key                  string `mapstructure:"key" yaml:"key"`
	CA                   string `mapstructure:"ca" yaml:"ca"`
	AuthzID              string `mapstructure:"authz_id" yaml:"authz_id"`
	BindDN               string `mapstructure:"binddn" yaml:"binddn"`
	BindPW               string `mapstructure:"bindpw" yaml:"bindpw"`
	AllowInsecure        bool   `mapstructure:"allow_insecure" yaml:"allow_insecure"`
	DestinationIndicator string `mapstructure:"destination_indicator" yaml:"destination_indicator"`
	ServiceType          string `mapstructure:"service_type" yaml:"service_type"`
}

type DNSConfig struct {
	PrimaryNameserver string `mapstructure:"primary_nameserver" yaml:"primary_nameserver"`
	TSIGKeyFile       string `mapstructure:"tsig_key_file" yaml:"tsig_key_file"`
	TSIGKeyName       string `mapstructure:"tsig_key_name" yaml:"tsig_key_name"`
	Algorithm         string `mapstructure:"algorithm" yaml:"algorithm"`
	TTL               int    `mapstructure:"ttl" yaml:"ttl"`
	CNAMEs            string `mapstructure:"cnames" yaml:"cnames"`
}

type Config struct {
	Global GlobalConfig `mapstructure:"global" yaml:"global"`
	LDAP   LDAPConfig   `mapstructure:"ldap" yaml:"ldap"`
	DNS    DNSConfig    `mapstructure:"dns" yaml:"dns"`

	ResolvedPath string            `mapstructure:"-" yaml:"-"`
	Scheme       types.Scheme      `mapstructure:"-" yaml:"-"`
	KeyType      types.DKIMKeyType `mapstructure:"-" yaml:"-"`
}

func defaultConfig() Config {
	return Config{
		Global: GlobalConfig{
			DeleteDelay:                10,
			ExpireAfter:                365,
			UseDKIMIdentity:            false,
			TerminalBackground:         "dark",
			KeyType:                    "both",
			MaxRevoked:                 6,
			RevokedRetention:           30,
			CNAMESelectorRSAPrefix:     "selector-rsa-",
			CNAMESelectorED25519Prefix: "selector-ed25519-",
		},
		LDAP: LDAPConfig{
			DomainAttribute:      "associatedDomain",
			DestinationIndicator: "destinationIndicator",
			ServiceType:          "description",
		},
		DNS: DNSConfig{
			Algorithm: "hmac_sha256",
		},
		Scheme: types.DefaultScheme(),
	}
}

func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultConfigPath
	}

	cfg := defaultConfig()
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("OPENDKIM_MANAGE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := strictDecode(path, &cfg); err != nil {
		return nil, err
	}

	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	cfg.ResolvedPath = v.ConfigFileUsed()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func strictDecode(path string, out *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid config schema: %w", err)
	}
	return nil
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.LDAP.URI) == "" {
		return errors.New("ldap.uri is required")
	}
	if strings.TrimSpace(c.LDAP.DomainAttribute) == "" {
		return errors.New("ldap.domain is required")
	}
	if c.Global.DeleteDelay < 0 {
		return errors.New("global.delete_delay must be >= 0")
	}
	if c.Global.ExpireAfter <= 0 {
		return errors.New("global.expire_after must be > 0")
	}
	if c.Global.MaxRevoked < 0 {
		return errors.New("global.max_revoked must be >= 0")
	}
	if c.Global.RevokedRetention < 0 {
		return errors.New("global.revoked_retention must be >= 0")
	}
	if c.Global.DeleteDelay > 36500 || c.Global.ExpireAfter > 36500 || c.Global.RevokedRetention > 36500 {
		return errors.New("lifecycle day values must be <= 36500")
	}

	ldapURI, err := url.Parse(c.LDAP.URI)
	if err != nil {
		return fmt.Errorf("ldap.uri: %w", err)
	}
	if ldapURI.Scheme != "ldap" && ldapURI.Scheme != "ldaps" {
		return fmt.Errorf("ldap.uri uses unsupported scheme %q", ldapURI.Scheme)
	}
	if strings.TrimSpace(ldapURI.Host) == "" {
		return errors.New("ldap.uri host is required")
	}
	secureTransport := strings.EqualFold(ldapURI.Scheme, "ldaps") || c.LDAP.UseStartTLS
	if !secureTransport && !c.LDAP.AllowInsecure {
		return errors.New("ldap transport must use ldaps or use_starttls; set ldap.allow_insecure only for an explicit legacy exception")
	}
	reqCert := strings.ToLower(strings.TrimSpace(c.LDAP.ReqCert))
	if (reqCert == "never" || reqCert == "allow" || reqCert == "try") && !c.LDAP.AllowInsecure {
		return errors.New("ldap.reqcert must be demand unless ldap.allow_insecure is explicitly enabled")
	}
	bindMethod := strings.ToLower(strings.TrimSpace(c.LDAP.BindMethod))
	saslMech := strings.ToLower(strings.TrimSpace(c.LDAP.SASLMech))
	switch bindMethod {
	case "", "simple":
		if saslMech != "" {
			return errors.New("ldap.saslmech requires ldap.bindmethod=sasl")
		}
	case "sasl":
		if saslMech != "external" {
			return fmt.Errorf("ldap.saslmech %q is not implemented; only external is supported", c.LDAP.SASLMech)
		}
		if strings.TrimSpace(c.LDAP.Cert) == "" || strings.TrimSpace(c.LDAP.Key) == "" {
			return errors.New("ldap SASL EXTERNAL requires both ldap.cert and ldap.key")
		}
	default:
		return fmt.Errorf("ldap.bindmethod unsupported: %s", c.LDAP.BindMethod)
	}
	if (strings.TrimSpace(c.LDAP.Cert) == "") != (strings.TrimSpace(c.LDAP.Key) == "") {
		return errors.New("ldap.cert and ldap.key must be configured together")
	}
	if strings.TrimSpace(c.LDAP.Ciphers) != "" {
		return errors.New("ldap.ciphers is not implemented and must be empty")
	}
	if strings.TrimSpace(c.LDAP.AuthzID) != "" {
		return errors.New("ldap.authz_id is not implemented and must be empty")
	}

	if strings.EqualFold(c.Global.CNAMESelectorRSAPrefix, c.Global.CNAMESelectorED25519Prefix) {
		return errors.New("cname selector prefixes must not be equal")
	}

	kt, err := types.ParseDKIMKeyType(strings.ToLower(strings.TrimSpace(c.Global.KeyType)))
	if err != nil {
		return fmt.Errorf("global.keytype: %w", err)
	}
	if kt == types.DKIMKeyTypeUnknown || kt == types.DKIMKeyTypeRevoked {
		return fmt.Errorf("global.keytype unsupported: %s", c.Global.KeyType)
	}
	c.KeyType = kt

	if bg := strings.ToLower(strings.TrimSpace(c.Global.TerminalBackground)); bg == "" {
		c.Global.TerminalBackground = "dark"
	} else if bg != "dark" && bg != "light" {
		return errors.New("global.terminal_background must be 'dark' or 'light'")
	}

	if algo := strings.ToLower(strings.TrimSpace(c.DNS.Algorithm)); algo != "" {
		switch algo {
		case "hmac_sha256", "hmac_sha384", "hmac_sha512":
		default:
			return fmt.Errorf("dns.algorithm unsupported: %s", c.DNS.Algorithm)
		}
	}
	if c.DNS.TTL < 0 {
		return errors.New("dns.ttl must be >= 0")
	}
	if (strings.TrimSpace(c.DNS.TSIGKeyName) == "") != (strings.TrimSpace(c.DNS.TSIGKeyFile) == "") {
		return errors.New("dns.tsig_key_name and dns.tsig_key_file must be configured together")
	}

	c.Scheme = types.DefaultScheme()
	c.Scheme.AssociatedDomain = c.LDAP.DomainAttribute
	if c.LDAP.DestinationIndicator != "" {
		c.Scheme.DestinationIndicator = c.LDAP.DestinationIndicator
	}
	if c.LDAP.ServiceType != "" {
		c.Scheme.ServiceType = c.LDAP.ServiceType
	}

	return nil
}

func (c *Config) DNSAlgorithmFQDN() string {
	switch strings.ToLower(strings.TrimSpace(c.DNS.Algorithm)) {
	case "hmac_sha384":
		return "hmac-sha384."
	case "hmac_sha512":
		return "hmac-sha512."
	default:
		return "hmac-sha256."
	}
}

func (c *Config) DNSConfigured() bool {
	return strings.TrimSpace(c.DNS.PrimaryNameserver) != "" && c.DNS.TTL > 0
}

func (c *Config) AuthenticatedDNSUpdatesConfigured() bool {
	return c.DNSConfigured() && strings.TrimSpace(c.DNS.TSIGKeyName) != "" && strings.TrimSpace(c.DNS.TSIGKeyFile) != ""
}
