package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

const DefaultConfigPath = "/etc/opendkim-manage.yaml"

type GlobalConfig struct {
	Mode                       types.Mode `mapstructure:"mode" yaml:"mode"`
	DeleteDelay                int        `mapstructure:"delete_delay" yaml:"delete_delay"`
	ExpireAfter                int        `mapstructure:"expire_after" yaml:"expire_after"`
	SelectorFormat             string     `mapstructure:"selectorformat" yaml:"selectorformat"`
	UseDKIMIdentity            bool       `mapstructure:"use_dkim_identity" yaml:"use_dkim_identity"`
	TerminalBackground         string     `mapstructure:"terminal_background" yaml:"terminal_background"`
	KeyType                    string     `mapstructure:"keytype" yaml:"keytype"`
	MaxRevoked                 int        `mapstructure:"max_revoked" yaml:"max_revoked"`
	RevokedRetention           int        `mapstructure:"revoked_retention" yaml:"revoked_retention"`
	CNAMESelectorRSAPrefix     string     `mapstructure:"cname_selector_rsa_prefix" yaml:"cname_selector_rsa_prefix"`
	CNAMESelectorED25519Prefix string     `mapstructure:"cname_selector_ed25519_prefix" yaml:"cname_selector_ed25519_prefix"`
	MultipleSignaturesDomains  []string   `mapstructure:"multiple_signatures_domains" yaml:"multiple_signatures_domains"`
}

// DKIM2Config contains the closed policy inputs needed to construct a native DKIM2 dataset.
type DKIM2Config struct {
	TenantID                          string               `mapstructure:"tenant_id" yaml:"tenant_id"`
	ProfileUse                        string               `mapstructure:"profile_use" yaml:"profile_use"`
	Rollout                           string               `mapstructure:"rollout" yaml:"rollout"`
	Compatibility                     string               `mapstructure:"compatibility" yaml:"compatibility"`
	FeedbackRouteID                   string               `mapstructure:"feedback_route_id" yaml:"feedback_route_id"`
	RotationEnabled                   bool                 `mapstructure:"rotation_enabled" yaml:"rotation_enabled"`
	RotateAfterDays                   int                  `mapstructure:"rotate_after_days" yaml:"rotate_after_days"`
	HistoryLimit                      int                  `mapstructure:"history_limit" yaml:"history_limit"`
	MaxCampaignBindings               int                  `mapstructure:"max_campaign_bindings" yaml:"max_campaign_bindings"`
	MaxGenerationEntries              int                  `mapstructure:"max_generation_entries" yaml:"max_generation_entries"`
	MaxAttributeBytes                 int                  `mapstructure:"max_attribute_bytes" yaml:"max_attribute_bytes"`
	MaxDatasetBytes                   int                  `mapstructure:"max_dataset_bytes" yaml:"max_dataset_bytes"`
	MaxLDAPRequests                   int                  `mapstructure:"max_ldap_requests" yaml:"max_ldap_requests"`
	MaxLDAPBytes                      int                  `mapstructure:"max_ldap_bytes" yaml:"max_ldap_bytes"`
	MaxRetainedRootVisits             int                  `mapstructure:"max_retained_root_visits" yaml:"max_retained_root_visits"`
	IdentifierAllocationAttempts      int                  `mapstructure:"identifier_allocation_attempts" yaml:"identifier_allocation_attempts"`
	PublicationReadbackAttempts       int                  `mapstructure:"publication_readback_attempts" yaml:"publication_readback_attempts"`
	PublicationReadbackIntervalMillis int                  `mapstructure:"publication_readback_interval_millis" yaml:"publication_readback_interval_millis"`
	LDAPSearchTimeLimitSeconds        int                  `mapstructure:"ldap_search_time_limit_seconds" yaml:"ldap_search_time_limit_seconds"`
	LDAPOperationTimeoutSeconds       int                  `mapstructure:"ldap_operation_timeout_seconds" yaml:"ldap_operation_timeout_seconds"`
	AuthorityPasswordMaxBytes         int                  `mapstructure:"authority_password_max_bytes" yaml:"authority_password_max_bytes"`
	AuthorityPasswordPreserveNewline  bool                 `mapstructure:"authority_password_preserve_trailing_newline" yaml:"authority_password_preserve_trailing_newline"`
	MaxClockSkewSeconds               int                  `mapstructure:"max_clock_skew_seconds" yaml:"max_clock_skew_seconds"`
	RunTimeoutSeconds                 int                  `mapstructure:"run_timeout_seconds" yaml:"run_timeout_seconds"`
	ProofPollIntervalSeconds          int                  `mapstructure:"proof_poll_interval_seconds" yaml:"proof_poll_interval_seconds"`
	ProofMaxAttempts                  int                  `mapstructure:"proof_max_attempts" yaml:"proof_max_attempts"`
	DNSQueryTimeoutSeconds            int                  `mapstructure:"dns_query_timeout_seconds" yaml:"dns_query_timeout_seconds"`
	RetirementMinOverlapSeconds       int                  `mapstructure:"retirement_min_overlap_seconds" yaml:"retirement_min_overlap_seconds"`
	Retention                         DKIM2RetentionConfig `mapstructure:"retention" yaml:"retention"`
	LDAPAuthorities                   DKIM2LDAPAuthorities `mapstructure:"ldap_authorities" yaml:"ldap_authorities"`
}

// DKIM2RetentionConfig contains every bounded automatic history-deletion policy.
type DKIM2RetentionConfig struct {
	Enabled                bool   `mapstructure:"enabled" yaml:"enabled"`
	MaxGenerations         int    `mapstructure:"max_generations" yaml:"max_generations"`
	MinRollbackGenerations int    `mapstructure:"min_rollback_generations" yaml:"min_rollback_generations"`
	MaxDeleteBatch         int    `mapstructure:"max_delete_batch" yaml:"max_delete_batch"`
	JournalFile            string `mapstructure:"journal_file" yaml:"journal_file"`
	MaxJournalBytes        int    `mapstructure:"max_journal_bytes" yaml:"max_journal_bytes"`
}

// DKIM2LDAPAuthority identifies one least-privilege simple-bind role.
type DKIM2LDAPAuthority struct {
	BindDN       string `mapstructure:"bind_dn" yaml:"bind_dn"`
	PasswordFile string `mapstructure:"password_file" yaml:"password_file"`
}

// DKIM2LDAPAuthorities separates automatic campaign read and write ownership.
type DKIM2LDAPAuthorities struct {
	Snapshot   DKIM2LDAPAuthority `mapstructure:"snapshot" yaml:"snapshot"`
	Staging    DKIM2LDAPAuthority `mapstructure:"staging" yaml:"staging"`
	Activation DKIM2LDAPAuthority `mapstructure:"activation" yaml:"activation"`
	Purge      DKIM2LDAPAuthority `mapstructure:"purge" yaml:"purge"`
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
	PrimaryNameserver   string `mapstructure:"primary_nameserver" yaml:"primary_nameserver"`
	RecursiveNameserver string `mapstructure:"recursive_nameserver" yaml:"recursive_nameserver"`
	TSIGKeyFile         string `mapstructure:"tsig_key_file" yaml:"tsig_key_file"`
	TSIGKeyName         string `mapstructure:"tsig_key_name" yaml:"tsig_key_name"`
	Algorithm           string `mapstructure:"algorithm" yaml:"algorithm"`
	TTL                 int    `mapstructure:"ttl" yaml:"ttl"`
	CNAMEs              string `mapstructure:"cnames" yaml:"cnames"`
}

type Config struct {
	Global GlobalConfig `mapstructure:"global" yaml:"global"`
	LDAP   LDAPConfig   `mapstructure:"ldap" yaml:"ldap"`
	DNS    DNSConfig    `mapstructure:"dns" yaml:"dns"`
	DKIM2  DKIM2Config  `mapstructure:"dkim2" yaml:"dkim2"`

	ResolvedPath string            `mapstructure:"-" yaml:"-"`
	Scheme       types.Scheme      `mapstructure:"-" yaml:"-"`
	KeyType      types.DKIMKeyType `mapstructure:"-" yaml:"-"`
}

func defaultConfig() Config {
	return Config{
		Global: GlobalConfig{
			Mode:                       types.ModeOpenDKIM,
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
			Algorithm: "hmac_sha256", PrimaryNameserver: "127.0.0.1:53",
			RecursiveNameserver: "127.0.0.2:53",
		},
		DKIM2: DKIM2Config{
			RotateAfterDays: 30, HistoryLimit: 16384, MaxCampaignBindings: 16384,
			MaxGenerationEntries: 131072, MaxAttributeBytes: 64 << 10, MaxDatasetBytes: 1 << 30,
			MaxLDAPRequests: 262144, MaxLDAPBytes: 1 << 30, MaxRetainedRootVisits: 32768,
			IdentifierAllocationAttempts: 32, PublicationReadbackAttempts: 8,
			PublicationReadbackIntervalMillis: 25, LDAPSearchTimeLimitSeconds: 30,
			LDAPOperationTimeoutSeconds: 60, AuthorityPasswordMaxBytes: 16 << 10,
			MaxClockSkewSeconds: 300, RunTimeoutSeconds: 86400,
			ProofPollIntervalSeconds: 5, ProofMaxAttempts: 3600,
			DNSQueryTimeoutSeconds: 5, RetirementMinOverlapSeconds: 604800,
			Retention: DKIM2RetentionConfig{Enabled: true, MaxGenerations: 12, MinRollbackGenerations: 2, MaxDeleteBatch: 64,
				JournalFile: "/var/lib/opendkim-manage-go/dkim2-retention-plan.json", MaxJournalBytes: 4096},
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
	if err := validateExplicitMode(b); err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid config schema: %w", err)
	}
	return nil
}

// validateExplicitMode distinguishes an omitted default from an explicit YAML
// null or empty value before Viper merges the document into initialized defaults.
func validateExplicitMode(document []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(document, &root); err != nil {
		return fmt.Errorf("invalid config schema: %w", err)
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return errors.New("invalid config schema: document must be a mapping")
	}
	global := yamlMappingValue(root.Content[0], "global")
	if global == nil {
		return nil
	}
	if global.Kind != yaml.MappingNode {
		return errors.New("invalid config schema: global must be a mapping")
	}
	mode := yamlMappingValue(global, "mode")
	if mode == nil {
		return nil
	}
	if mode.Kind != yaml.ScalarNode || mode.Tag != "!!str" || mode.Value == "" {
		return errors.New("global.mode must be an explicit non-empty string when present")
	}
	return nil
}

// yamlMappingValue returns one exact mapping value or nil when the key is absent.
func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func (c *Config) Validate() error {
	if err := c.ValidateForMode(c.Global.Mode); err != nil {
		return err
	}
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

// ValidateForMode validates the selected mode before its implementation is constructed.
func (c *Config) ValidateForMode(mode types.Mode) error {
	if c == nil {
		return errors.New("config is required")
	}
	if _, err := types.ParseMode(string(mode)); err != nil {
		return fmt.Errorf("global.mode: %w", err)
	}
	if mode == types.ModeDKIM2 || c.DKIM2.configured() {
		if err := c.DKIM2.validate(); err != nil {
			return err
		}
		if c.DKIM2.RotationEnabled {
			if method := strings.ToLower(strings.TrimSpace(c.LDAP.BindMethod)); method != "" && method != "simple" {
				return errors.New("DKIM2 automatic rotation requires simple-bind role authorities")
			}
		}
		primary, err := canonicalEndpoint(c.DNS.PrimaryNameserver)
		if err != nil {
			return fmt.Errorf("dns.primary_nameserver: %w", err)
		}
		recursive, err := canonicalEndpoint(c.DNS.RecursiveNameserver)
		if err != nil {
			return fmt.Errorf("dns.recursive_nameserver: %w", err)
		}
		if primary == recursive {
			return errors.New("DKIM2 authoritative and recursive DNS endpoints must be distinct")
		}
		c.DNS.PrimaryNameserver = primary
		c.DNS.RecursiveNameserver = recursive
	}
	return nil
}

// configured reports whether any DKIM2-only field was supplied.
func (c DKIM2Config) configured() bool {
	return c.TenantID != "" || c.ProfileUse != "" || c.Rollout != "" || c.Compatibility != "" || c.FeedbackRouteID != ""
}

// validate enforces the complete closed DKIM2 policy contract.
func (c DKIM2Config) validate() error {
	if !canonicalIdentifier(c.TenantID) {
		return errors.New("dkim2.tenant_id must be a lowercase ASCII identifier of at most 128 bytes")
	}
	use, err := dkim2model.ParseProfileUse(c.ProfileUse)
	if err != nil || !use.SupportsNativeKeyCustody() {
		return errors.New("dkim2.profile_use must be originator, ordinary_transit, or delivery_status for native key custody")
	}
	switch c.Rollout {
	case "enforce", "observe", "off":
	default:
		return errors.New("dkim2.rollout must be enforce, observe, or off")
	}
	if c.Compatibility != "strict" {
		return errors.New("dkim2.compatibility must be strict")
	}
	if c.FeedbackRouteID != "" && !canonicalIdentifier(c.FeedbackRouteID) {
		return errors.New("dkim2.feedback_route_id must be empty or a lowercase ASCII identifier of at most 128 bytes")
	}
	if c.RotateAfterDays < 1 || c.RotateAfterDays > 36500 {
		return errors.New("dkim2.rotate_after_days must be between 1 and 36500")
	}
	if c.HistoryLimit < 2 || c.HistoryLimit > 16384 {
		return errors.New("dkim2.history_limit must be between 2 and 16384")
	}
	if c.MaxCampaignBindings < 1 || c.MaxCampaignBindings > 1000000 {
		return errors.New("dkim2.max_campaign_bindings must be between 1 and 1000000")
	}
	if c.MaxGenerationEntries < 6 || c.MaxGenerationEntries > 1000000 {
		return errors.New("dkim2.max_generation_entries must be between 6 and 1000000")
	}
	if c.MaxAttributeBytes < 1024 || c.MaxAttributeBytes > 1<<20 {
		return errors.New("dkim2.max_attribute_bytes must be between 1024 and 1048576")
	}
	if c.MaxDatasetBytes < 1<<20 || c.MaxDatasetBytes > 1<<30 {
		return errors.New("dkim2.max_dataset_bytes must be between 1048576 and 1073741824")
	}
	if c.MaxLDAPRequests < 32 || c.MaxLDAPRequests > 1000000 {
		return errors.New("dkim2.max_ldap_requests must be between 32 and 1000000")
	}
	if c.MaxLDAPBytes < c.MaxDatasetBytes || c.MaxLDAPBytes > 1<<30 {
		return errors.New("dkim2.max_ldap_bytes must be at least max_dataset_bytes and at most 1073741824")
	}
	if c.MaxRetainedRootVisits < c.HistoryLimit || c.MaxRetainedRootVisits > 1000000 {
		return errors.New("dkim2.max_retained_root_visits must be at least history_limit and at most 1000000")
	}
	if c.IdentifierAllocationAttempts < 1 || c.IdentifierAllocationAttempts > 1024 {
		return errors.New("dkim2.identifier_allocation_attempts must be between 1 and 1024")
	}
	if c.PublicationReadbackAttempts < 1 || c.PublicationReadbackAttempts > 128 {
		return errors.New("dkim2.publication_readback_attempts must be between 1 and 128")
	}
	if c.PublicationReadbackIntervalMillis < 1 || c.PublicationReadbackIntervalMillis > 10000 {
		return errors.New("dkim2.publication_readback_interval_millis must be between 1 and 10000")
	}
	if c.LDAPSearchTimeLimitSeconds < 1 || c.LDAPSearchTimeLimitSeconds > 300 {
		return errors.New("dkim2.ldap_search_time_limit_seconds must be between 1 and 300")
	}
	if c.LDAPOperationTimeoutSeconds < 1 || c.LDAPOperationTimeoutSeconds > 3600 {
		return errors.New("dkim2.ldap_operation_timeout_seconds must be between 1 and 3600")
	}
	if c.AuthorityPasswordMaxBytes < 1 || c.AuthorityPasswordMaxBytes > 1<<20 {
		return errors.New("dkim2.authority_password_max_bytes must be between 1 and 1048576")
	}
	if c.MaxClockSkewSeconds < 0 || c.MaxClockSkewSeconds > 3600 {
		return errors.New("dkim2.max_clock_skew_seconds must be between 0 and 3600")
	}
	if c.RunTimeoutSeconds < 30 || c.RunTimeoutSeconds > 86400 {
		return errors.New("dkim2.run_timeout_seconds must be between 30 and 86400")
	}
	if c.ProofPollIntervalSeconds < 1 || c.ProofPollIntervalSeconds > 300 {
		return errors.New("dkim2.proof_poll_interval_seconds must be between 1 and 300")
	}
	if c.ProofMaxAttempts < 1 || c.ProofMaxAttempts > 3600 {
		return errors.New("dkim2.proof_max_attempts must be between 1 and 3600")
	}
	if c.DNSQueryTimeoutSeconds < 1 || c.DNSQueryTimeoutSeconds > 30 {
		return errors.New("dkim2.dns_query_timeout_seconds must be between 1 and 30")
	}
	if c.RetirementMinOverlapSeconds < 3600 || c.RetirementMinOverlapSeconds > 31536000 {
		return errors.New("dkim2.retirement_min_overlap_seconds must be between 3600 and 31536000")
	}
	if c.Retention.MaxGenerations < 1 || c.Retention.MaxGenerations > c.HistoryLimit {
		return errors.New("dkim2.retention.max_generations must be between 1 and history_limit")
	}
	if c.Retention.MinRollbackGenerations < 0 || c.Retention.MinRollbackGenerations >= c.Retention.MaxGenerations {
		return errors.New("dkim2.retention.min_rollback_generations must be at least 0 and less than max_generations")
	}
	if c.Retention.MaxDeleteBatch < 1 || c.Retention.MaxDeleteBatch > c.HistoryLimit {
		return errors.New("dkim2.retention.max_delete_batch must be between 1 and history_limit")
	}
	if c.Retention.MaxJournalBytes < 512 || c.Retention.MaxJournalBytes > 1<<20 {
		return errors.New("dkim2.retention.max_journal_bytes must be between 512 and 1048576")
	}
	if (c.RotationEnabled && c.Retention.Enabled || c.Retention.JournalFile != "") &&
		(c.Retention.JournalFile == "" || !filepath.IsAbs(c.Retention.JournalFile) ||
			filepath.Clean(c.Retention.JournalFile) != c.Retention.JournalFile) {
		return errors.New("dkim2.retention.journal_file must be one clean absolute path")
	}
	if c.RotationEnabled {
		if strings.EqualFold(strings.TrimSpace(c.LDAPAuthorities.Snapshot.BindDN), strings.TrimSpace(c.LDAPAuthorities.Staging.BindDN)) ||
			strings.EqualFold(strings.TrimSpace(c.LDAPAuthorities.Snapshot.BindDN), strings.TrimSpace(c.LDAPAuthorities.Activation.BindDN)) ||
			strings.EqualFold(strings.TrimSpace(c.LDAPAuthorities.Snapshot.BindDN), strings.TrimSpace(c.LDAPAuthorities.Purge.BindDN)) ||
			strings.EqualFold(strings.TrimSpace(c.LDAPAuthorities.Staging.BindDN), strings.TrimSpace(c.LDAPAuthorities.Activation.BindDN)) ||
			strings.EqualFold(strings.TrimSpace(c.LDAPAuthorities.Staging.BindDN), strings.TrimSpace(c.LDAPAuthorities.Purge.BindDN)) ||
			strings.EqualFold(strings.TrimSpace(c.LDAPAuthorities.Activation.BindDN), strings.TrimSpace(c.LDAPAuthorities.Purge.BindDN)) {
			return errors.New("dkim2.ldap_authorities bind DNs must be distinct")
		}
		paths := make(map[string]struct{}, 4)
		for name, authority := range map[string]DKIM2LDAPAuthority{
			"snapshot": c.LDAPAuthorities.Snapshot, "staging": c.LDAPAuthorities.Staging,
			"activation": c.LDAPAuthorities.Activation, "purge": c.LDAPAuthorities.Purge,
		} {
			if err := validateDKIM2LDAPAuthority(authority); err != nil {
				return fmt.Errorf("dkim2.ldap_authorities.%s: %w", name, err)
			}
			if _, duplicate := paths[authority.PasswordFile]; duplicate {
				return errors.New("dkim2.ldap_authorities password files must be distinct")
			}
			paths[authority.PasswordFile] = struct{}{}
			if authority.PasswordFile == c.Retention.JournalFile {
				return errors.New("dkim2 retention journal and authority password files must be distinct")
			}
		}
	}
	return nil
}

func validateDKIM2LDAPAuthority(authority DKIM2LDAPAuthority) error {
	bindDN := strings.TrimSpace(authority.BindDN)
	parsed, err := ldap.ParseDN(bindDN)
	if err != nil || bindDN == "" || parsed.String() != bindDN {
		return errors.New("bind_dn must be one canonical non-empty LDAP DN")
	}
	if authority.PasswordFile == "" || !filepath.IsAbs(authority.PasswordFile) ||
		filepath.Clean(authority.PasswordFile) != authority.PasswordFile {
		return errors.New("password_file must be one clean absolute path")
	}
	return nil
}

// canonicalEndpoint requires one normalized explicit host-or-IP and port.
func canonicalEndpoint(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", errors.New("must be a canonical host or IP with explicit port")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return "", errors.New("must be a canonical host or IP with explicit port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return "", errors.New("port must be a canonical integer between 1 and 65535")
	}
	if address, addressErr := netip.ParseAddr(host); addressErr == nil {
		if address.Zone() != "" || address.String() != host {
			return "", errors.New("IP address must be canonical")
		}
		return net.JoinHostPort(address.String(), portText), nil
	}
	canonical, err := dkim2model.CanonicalDomain(host)
	if err != nil || canonical != host {
		return "", errors.New("host must be a canonical lowercase ASCII name")
	}
	return net.JoinHostPort(canonical, portText), nil
}

// canonicalIdentifier validates the bounded DKIM2 identifier grammar.
func canonicalIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
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
