package dnsupdate

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

// ExpectedTXT identifies one absolute DKIM TXT owner and its preferred canonical content.
type ExpectedTXT struct {
	Owner   string
	Content string
}

const expectedTXTRedacted = "<redacted DKIM2 DNS expectation>"

// String prevents generic formatting from exposing DNS owners or public-key bytes.
func (ExpectedTXT) String() string { return expectedTXTRedacted }

// GoString prevents Go-syntax formatting from exposing DNS owners or public-key bytes.
func (ExpectedTXT) GoString() string { return expectedTXTRedacted }

// MarshalText prevents text encoders from exposing DNS owners or public-key bytes.
func (ExpectedTXT) MarshalText() ([]byte, error) { return []byte(expectedTXTRedacted), nil }

// MarshalJSON emits no DNS identity or public-key material.
func (ExpectedTXT) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// ProofChannel identifies one explicit direct DNS evidence path.
type ProofChannel uint8

const (
	ProofAuthoritative ProofChannel = iota + 1
	ProofRecursive
)

// ProofState is a closed key-equivalent classification of one direct DNS readback.
type ProofState uint8

const (
	ProofAbsent ProofState = iota + 1
	ProofExact
)

// PublishResult reports whether this call created the RRset or resumed an exact one.
type PublishResult uint8

const (
	PublishCreated PublishResult = iota + 1
	PublishAlreadyPresent
	PublishResumable
)

var (
	// ErrPublishResumable requires a later explicit invocation after proven absence.
	ErrPublishResumable = errors.New("DKIM2 DNS publication is explicitly resumable")
	// ErrPublishConflict identifies authoritative content that cannot be overwritten.
	ErrPublishConflict = errors.New("DKIM2 DNS publication conflicts with authoritative state")
	// ErrPublishUncertain identifies an outcome that lacks authoritative classification.
	ErrPublishUncertain = errors.New("DKIM2 DNS publication outcome is uncertain")
)

type dnsExchange func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error)

// ProofClient performs bounded TCP proof against explicit authoritative and recursive endpoints.
type ProofClient struct {
	primary      string
	recursive    string
	queryTimeout time.Duration
	pollInterval time.Duration
	runTimeout   time.Duration
	maxAttempts  int
	exchange     dnsExchange
	wait         func(context.Context, time.Duration) error
}

const proofClientRedacted = "<redacted DKIM2 DNS proof client>"

// String prevents generic formatting from exposing configured DNS endpoints.
func (*ProofClient) String() string { return proofClientRedacted }

// GoString prevents Go-syntax formatting from exposing configured DNS endpoints.
func (*ProofClient) GoString() string { return proofClientRedacted }

// MarshalText prevents text encoders from exposing configured DNS endpoints.
func (*ProofClient) MarshalText() ([]byte, error) { return []byte(proofClientRedacted), nil }

// MarshalJSON emits no configured DNS endpoints.
func (*ProofClient) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// NewProofClient validates and captures the closed DKIM2 proof-channel configuration.
func NewProofClient(cfg *config.Config) (*ProofClient, error) {
	if cfg == nil || cfg.DNS.PrimaryNameserver == "" || cfg.DNS.RecursiveNameserver == "" ||
		cfg.DNS.PrimaryNameserver == cfg.DNS.RecursiveNameserver || cfg.DKIM2.DNSQueryTimeoutSeconds < 1 ||
		cfg.DKIM2.ProofPollIntervalSeconds < 1 || cfg.DKIM2.ProofMaxAttempts < 1 {
		return nil, errors.New("invalid DKIM2 DNS proof configuration")
	}
	return &ProofClient{
		primary: cfg.DNS.PrimaryNameserver, recursive: cfg.DNS.RecursiveNameserver,
		queryTimeout: time.Duration(cfg.DKIM2.DNSQueryTimeoutSeconds) * time.Second,
		pollInterval: time.Duration(cfg.DKIM2.ProofPollIntervalSeconds) * time.Second,
		runTimeout:   time.Duration(cfg.DKIM2.RunTimeoutSeconds) * time.Second,
		maxAttempts:  cfg.DKIM2.ProofMaxAttempts,
		exchange:     exchangeDNS,
		wait:         waitContext,
	}, nil
}

// ProveAll proves each credential through the authoritative channel before its recursive channel.
func (c *ProofClient) ProveAll(ctx context.Context, records []ExpectedTXT) error {
	if c == nil || len(records) == 0 {
		return errors.New("DKIM2 DNS proof requires at least one credential")
	}
	bound := c.pollInterval * time.Duration(c.maxAttempts)
	if c.runTimeout > 0 && c.runTimeout < bound {
		bound = c.runTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	for _, record := range records {
		if err := validateExpectedTXT(record); err != nil {
			return err
		}
		if err := c.poll(runCtx, record, ProofAuthoritative); err != nil {
			return err
		}
		if err := c.poll(runCtx, record, ProofRecursive); err != nil {
			return err
		}
	}
	return nil
}

func (c *ProofClient) poll(ctx context.Context, expected ExpectedTXT, channel ProofChannel) error {
	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := c.lookup(ctx, expected, channel)
		if err != nil {
			return err
		}
		if state == ProofExact {
			return nil
		}
		if attempt+1 < c.maxAttempts {
			if err := c.wait(ctx, c.pollInterval); err != nil {
				return err
			}
		}
	}
	return errors.New("DKIM2 DNS proof remained pending within configured bounds")
}

func (c *ProofClient) lookup(ctx context.Context, expected ExpectedTXT, channel ProofChannel) (ProofState, error) {
	address := c.primary
	recursionDesired := false
	if channel == ProofRecursive {
		address = c.recursive
		recursionDesired = true
	}
	query := new(dns.Msg)
	query.SetQuestion(expected.Owner, dns.TypeTXT)
	query.RecursionDesired = recursionDesired
	queryCtx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	response, err := c.exchange(queryCtx, &dns.Client{Net: "tcp", Timeout: c.queryTimeout}, query, address)
	if err != nil {
		return 0, errors.New("DKIM2 DNS proof exchange failed")
	}
	if response != nil && response.Id != query.Id {
		return 0, errors.New("DKIM2 DNS proof response does not match the query")
	}
	return classifyProofResponse(response, expected, channel)
}

// RotationPublisher owns collision-safe create-if-absent DNS publication.
type RotationPublisher struct {
	primary       string
	ttl           int
	queryTimeout  time.Duration
	tsigName      string
	tsigFile      string
	tsigAlgorithm string
	exchange      dnsExchange
	loadTSIG      func(string) ([]byte, error)
	lookup        func(context.Context, ExpectedTXT) (ProofState, error)
}

const rotationPublisherRedacted = "<redacted DKIM2 DNS rotation publisher>"

// String prevents generic formatting from exposing endpoints or TSIG metadata.
func (*RotationPublisher) String() string { return rotationPublisherRedacted }

// GoString prevents Go-syntax formatting from exposing endpoints or TSIG metadata.
func (*RotationPublisher) GoString() string { return rotationPublisherRedacted }

// MarshalText prevents text encoders from exposing endpoints or TSIG metadata.
func (*RotationPublisher) MarshalText() ([]byte, error) {
	return []byte(rotationPublisherRedacted), nil
}

// MarshalJSON emits no endpoints or TSIG metadata.
func (*RotationPublisher) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// NewRotationPublisher constructs a publisher without opening the TSIG key file.
func NewRotationPublisher(cfg *config.Config) (*RotationPublisher, error) {
	if cfg == nil || cfg.DNS.PrimaryNameserver == "" || cfg.DNS.TTL <= 0 ||
		cfg.DKIM2.DNSQueryTimeoutSeconds < 1 ||
		strings.TrimSpace(cfg.DNS.TSIGKeyName) == "" || strings.TrimSpace(cfg.DNS.TSIGKeyFile) == "" {
		return nil, errors.New("invalid DKIM2 DNS publication configuration")
	}
	p := &RotationPublisher{
		primary: cfg.DNS.PrimaryNameserver, ttl: cfg.DNS.TTL,
		queryTimeout: time.Duration(cfg.DKIM2.DNSQueryTimeoutSeconds) * time.Second,
		tsigName:     dns.Fqdn(cfg.DNS.TSIGKeyName), tsigFile: cfg.DNS.TSIGKeyFile,
		tsigAlgorithm: cfg.DNSAlgorithmFQDN(), exchange: exchangeDNS, loadTSIG: readTSIGBytes,
	}
	p.lookup = func(ctx context.Context, expected ExpectedTXT) (ProofState, error) {
		query := new(dns.Msg)
		query.SetQuestion(expected.Owner, dns.TypeTXT)
		query.RecursionDesired = false
		queryCtx, cancel := context.WithTimeout(ctx, p.queryTimeout)
		defer cancel()
		response, err := p.exchange(queryCtx, &dns.Client{Net: "tcp", Timeout: p.queryTimeout}, query, p.primary)
		if err != nil {
			return 0, fmt.Errorf("%w: authoritative readback failed", ErrPublishUncertain)
		}
		if response != nil && response.Id != query.Id {
			return 0, fmt.Errorf("%w: authoritative readback does not match the query", ErrPublishUncertain)
		}
		return classifyPresenceResponse(response, expected)
	}
	return p, nil
}

// PublishIfAbsent proves current state, then creates one TXT RRset under NXRRSET.
func (p *RotationPublisher) PublishIfAbsent(ctx context.Context, zone string, expected ExpectedTXT) (PublishResult, error) {
	if p == nil || p.lookup == nil {
		return 0, errors.New("DKIM2 DNS publisher is unavailable")
	}
	if err := validateZoneOwner(zone, expected); err != nil {
		return 0, err
	}
	state, err := p.lookup(ctx, expected)
	if err != nil {
		return 0, err
	}
	if state == ProofExact {
		return PublishAlreadyPresent, nil
	}
	msg, err := buildCreateIfAbsentMessage(zone, expected.Owner, expected.Content, p.ttl)
	if err != nil {
		return 0, err
	}
	secret, err := p.loadTSIG(p.tsigFile)
	if err != nil {
		return 0, errors.New("load TSIG credential failed")
	}
	defer clear(secret)
	if len(secret) == 0 || p.tsigName == "." {
		return 0, errors.New("complete TSIG configuration is required")
	}
	secretText := string(secret)
	defer func() { secretText = "" }()
	msg.SetTsig(p.tsigName, p.tsigAlgorithm, 300, time.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: p.queryTimeout, TsigSecret: map[string]string{p.tsigName: secretText}}
	writeCtx, cancel := context.WithTimeout(ctx, p.queryTimeout)
	response, exchangeErr := p.exchange(writeCtx, client, msg, p.primary)
	cancel()
	client.TsigSecret[p.tsigName] = ""
	client.TsigSecret = nil
	authenticatedSuccess := exchangeErr == nil && validateRotationUpdateResponse(response, msg) == nil
	return p.reconcileWrite(ctx, expected, authenticatedSuccess)
}

// reconcileWrite performs one fresh authoritative readback and never retries a write.
func (p *RotationPublisher) reconcileWrite(ctx context.Context, expected ExpectedTXT, authenticatedSuccess bool) (PublishResult, error) {
	state, err := p.lookup(ctx, expected)
	if err != nil {
		if errors.Is(err, ErrPublishConflict) {
			return 0, ErrPublishConflict
		}
		return 0, ErrPublishUncertain
	}
	switch state {
	case ProofExact:
		if authenticatedSuccess {
			return PublishCreated, nil
		}
		return PublishAlreadyPresent, nil
	case ProofAbsent:
		return PublishResumable, ErrPublishResumable
	default:
		return 0, ErrPublishConflict
	}
}

func buildCreateIfAbsentMessage(zone, owner, content string, ttl int) (*dns.Msg, error) {
	expected := ExpectedTXT{Owner: owner, Content: content}
	if err := validateZoneOwner(zone, expected); err != nil || ttl <= 0 {
		return nil, errors.New("invalid DKIM2 DNS create-if-absent request")
	}
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)}, Txt: txtChunks(content)}
	msg := new(dns.Msg)
	msg.SetUpdate(zone)
	msg.RRsetNotUsed([]dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT}}})
	msg.Insert([]dns.RR{rr})
	return msg, nil
}

func classifyProofResponse(response *dns.Msg, expected ExpectedTXT, channel ProofChannel) (ProofState, error) {
	if response == nil || !response.Response || response.Truncated || response.Rcode != dns.RcodeSuccess || len(response.Question) != 1 ||
		response.Question[0].Name != expected.Owner || response.Question[0].Qtype != dns.TypeTXT ||
		response.Question[0].Qclass != dns.ClassINET {
		return 0, errors.New("DKIM2 DNS response is invalid")
	}
	if channel == ProofAuthoritative && !response.Authoritative {
		return 0, errors.New("DKIM2 authoritative DNS proof lacks authority")
	}
	if channel == ProofRecursive && (!response.RecursionAvailable || response.Authoritative) {
		return 0, errors.New("DKIM2 recursive DNS proof is not recursive evidence")
	}
	for _, authority := range response.Ns {
		if authority.Header().Rrtype != dns.TypeSOA {
			return 0, errors.New("DKIM2 DNS referral is forbidden")
		}
	}
	if len(response.Answer) == 0 {
		return ProofAbsent, nil
	}
	if len(response.Answer) != 1 {
		return 0, errors.New("DKIM2 DNS RRset is ambiguous")
	}
	txt, ok := response.Answer[0].(*dns.TXT)
	if !ok || txt.Hdr.Name != expected.Owner || txt.Hdr.Class != dns.ClassINET {
		return 0, errors.New("DKIM2 DNS answer is conflicting")
	}
	content := strings.Join(txt.Txt, "")
	if !matchingDKIMContent(expected.Content, content) {
		return 0, errors.New("DKIM2 DNS answer does not match the staged credential")
	}
	return ProofExact, nil
}

// classifyPresenceResponse permits authoritative NXDOMAIN only for the
// publication pre-read; activation proof remains positive and exact-only.
func classifyPresenceResponse(response *dns.Msg, expected ExpectedTXT) (ProofState, error) {
	if response == nil || !response.Response || response.Truncated || len(response.Question) != 1 {
		return 0, fmt.Errorf("%w: invalid authoritative presence response", ErrPublishUncertain)
	}
	if response.Question[0].Name != expected.Owner || response.Question[0].Qtype != dns.TypeTXT ||
		response.Question[0].Qclass != dns.ClassINET {
		return 0, fmt.Errorf("%w: authoritative presence question differs", ErrPublishUncertain)
	}
	if response.Rcode == dns.RcodeSuccess {
		state, err := classifyProofResponse(response, expected, ProofAuthoritative)
		if err != nil {
			return 0, fmt.Errorf("%w: authoritative RRset differs or is ambiguous", ErrPublishConflict)
		}
		return state, nil
	}
	if response.Rcode != dns.RcodeNameError || !response.Authoritative || len(response.Answer) != 0 || len(response.Ns) != 1 {
		return 0, fmt.Errorf("%w: response is not authoritative absence", ErrPublishConflict)
	}
	soa, ok := response.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Class != dns.ClassINET || !absoluteCanonicalName(soa.Hdr.Name) ||
		!dns.IsSubDomain(soa.Hdr.Name, expected.Owner) {
		return 0, fmt.Errorf("%w: NXDOMAIN lacks matching SOA authority", ErrPublishConflict)
	}
	return ProofAbsent, nil
}

func validateExpectedTXT(expected ExpectedTXT) error {
	if !absoluteCanonicalName(expected.Owner) || validateDKIMContent(expected.Content) != nil {
		return errors.New("invalid DKIM2 DNS expectation")
	}
	return nil
}

func validateZoneOwner(zone string, expected ExpectedTXT) error {
	if err := validateExpectedTXT(expected); err != nil || !absoluteCanonicalName(zone) || !dns.IsSubDomain(zone, expected.Owner) {
		return errors.New("invalid absolute DKIM2 DNS zone or owner")
	}
	return nil
}

func absoluteCanonicalName(value string) bool {
	if value == "" || value != strings.ToLower(value) || dns.Fqdn(value) != value || strings.Contains(value, "\\") {
		return false
	}
	_, ok := dns.IsDomainName(value)
	return ok
}

func validateDKIMContent(content string) error {
	_, _, err := parseDKIMContent(content)
	return err
}

// matchingDKIMContent accepts exact records and equivalent canonical RSA encodings.
func matchingDKIMContent(expected, observed string) bool {
	if expected == observed {
		return validateDKIMContent(expected) == nil
	}
	expectedAlgorithm, expectedPublic, err := parseDKIMContent(expected)
	if err != nil {
		return false
	}
	defer clear(expectedPublic)
	observedAlgorithm, observedPublic, err := parseDKIMContent(observed)
	if err != nil || observedAlgorithm != expectedAlgorithm {
		clear(observedPublic)
		return false
	}
	defer clear(observedPublic)
	return dkim2model.DNSPublicKeyMatchesSPKI(expectedAlgorithm, expectedPublic, observedPublic) ||
		dkim2model.DNSPublicKeyMatchesSPKI(expectedAlgorithm, observedPublic, expectedPublic)
}

// parseDKIMContent validates the closed key-record shape and returns detached public bytes.
func parseDKIMContent(content string) (dkim2model.Algorithm, []byte, error) {
	parts := strings.Split(content, ";")
	values := make(map[string]string, len(parts))
	for index, raw := range parts {
		part := strings.TrimSpace(raw)
		if part == "" {
			return "", nil, errors.New("empty DKIM tag")
		}
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 || pair[0] == "" {
			return "", nil, errors.New("malformed DKIM tag")
		}
		if _, duplicate := values[pair[0]]; duplicate {
			return "", nil, errors.New("duplicate DKIM tag")
		}
		if index == 0 && (pair[0] != "v" || pair[1] != "DKIM1") {
			return "", nil, errors.New("invalid DKIM version")
		}
		values[pair[0]] = pair[1]
	}
	if len(values) != 4 || values["h"] != "sha256" || values["p"] == "" || (values["k"] != "rsa" && values["k"] != "ed25519") {
		return "", nil, errors.New("invalid DKIM key record")
	}
	public, err := base64.StdEncoding.Strict().DecodeString(values["p"])
	if err != nil || len(public) == 0 {
		clear(public)
		return "", nil, errors.New("invalid DKIM public key")
	}
	algorithm := dkim2model.AlgorithmRSASHA256
	if values["k"] == "ed25519" {
		algorithm = dkim2model.AlgorithmEd25519SHA256
	}
	return algorithm, public, nil
}

func readTSIGBytes(path string) (result []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil && closeErr != nil {
			clear(result)
			result = nil
			resultErr = closeErr
		}
	}()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Key:") {
			value := []byte(strings.TrimSpace(strings.TrimPrefix(line, "Key:")))
			if len(value) == 0 {
				return nil, errors.New("empty TSIG credential")
			}
			return value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("TSIG credential is missing")
}

func exchangeDNS(ctx context.Context, client *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
	response, _, err := client.ExchangeContext(ctx, msg, address)
	return response, err
}

// validateRotationUpdateResponse requires an authenticated matching success response.
func validateRotationUpdateResponse(response, request *dns.Msg) error {
	if err := validateRotationUpdateAuthentication(response, request); err != nil {
		return err
	}
	if response.Rcode != dns.RcodeSuccess {
		return errors.New("DKIM2 DNS update response was not successful")
	}
	return nil
}

// validateRotationUpdateAuthentication validates the signed response envelope independently of its RCODE.
func validateRotationUpdateAuthentication(response, request *dns.Msg) error {
	if request == nil || response == nil || !response.Response || response.Truncated ||
		response.Id != request.Id || response.Opcode != dns.OpcodeUpdate {
		return errors.New("invalid DKIM2 DNS update response")
	}
	if response.IsTsig() == nil {
		return errors.New("DKIM2 DNS update response lacks authentication")
	}
	return nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
