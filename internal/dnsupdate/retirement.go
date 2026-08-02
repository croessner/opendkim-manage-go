package dnsupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

// PresenceState is the closed direct-channel classification of one expected TXT RRset.
type PresenceState uint8

const (
	PresenceUncertain PresenceState = iota + 1
	PresenceAbsent
	PresenceExact
	PresenceConflict
)

// String returns only the closed state label and never protected DNS facts.
func (s PresenceState) String() string {
	switch s {
	case PresenceAbsent:
		return "absent"
	case PresenceExact:
		return "exact"
	case PresenceConflict:
		return "conflict"
	default:
		return "uncertain"
	}
}

// PresenceObserver exposes only a bounded, read-only authoritative presence check.
type PresenceObserver interface {
	Observe(context.Context, ExpectedTXT) (PresenceState, error)
}

// DualChannelPresenceObserver reports one bounded read from each configured proof channel.
type DualChannelPresenceObserver interface {
	ObserveChannels(context.Context, ExpectedTXT) (PresenceObservation, error)
}

// PresenceObservation contains only closed channel states and no DNS identities or endpoints.
type PresenceObservation struct {
	Authoritative PresenceState
	Recursive     PresenceState
}

// String exposes only the two closed channel state labels.
func (o PresenceObservation) String() string {
	return "authoritative=" + o.Authoritative.String() + " recursive=" + o.Recursive.String()
}

var (
	// ErrPresenceConflict identifies direct-channel content that differs from the expected RRset.
	ErrPresenceConflict = errors.New("DKIM2 DNS presence conflicts with authoritative state")
	// ErrPresenceUncertain identifies a response that cannot prove exact presence or absence.
	ErrPresenceUncertain = errors.New("DKIM2 DNS presence is uncertain")
	// ErrDeleteResumable requires explicit continuation after exact authoritative readback.
	ErrDeleteResumable = errors.New("DKIM2 DNS retirement is explicitly resumable")
	// ErrDeleteConflict identifies authoritative content that must not be deleted.
	ErrDeleteConflict = errors.New("DKIM2 DNS retirement conflicts with authoritative state")
	// ErrDeleteUncertain identifies a delete outcome that lacks authoritative classification.
	ErrDeleteUncertain = errors.New("DKIM2 DNS retirement outcome is uncertain")
)

// PresenceClient performs bounded direct-channel TXT observation without TSIG access.
type PresenceClient struct {
	primary      string
	recursive    string
	queryTimeout time.Duration
	exchange     dnsExchange
}

const presenceClientRedacted = "<redacted DKIM2 DNS presence client>"

// NewPresenceClient validates both read-only observation channels.
func NewPresenceClient(cfg *config.Config) (*PresenceClient, error) {
	if cfg == nil || strings.TrimSpace(cfg.DNS.PrimaryNameserver) == "" ||
		strings.TrimSpace(cfg.DNS.RecursiveNameserver) == "" ||
		cfg.DNS.PrimaryNameserver == cfg.DNS.RecursiveNameserver || cfg.DKIM2.DNSQueryTimeoutSeconds < 1 {
		return nil, errors.New("invalid DKIM2 DNS presence configuration")
	}
	return &PresenceClient{
		primary:      cfg.DNS.PrimaryNameserver,
		recursive:    cfg.DNS.RecursiveNameserver,
		queryTimeout: time.Duration(cfg.DKIM2.DNSQueryTimeoutSeconds) * time.Second,
		exchange:     exchangeDNS,
	}, nil
}

// Observe performs one direct authoritative TCP query and returns a closed state.
func (c *PresenceClient) Observe(ctx context.Context, expected ExpectedTXT) (PresenceState, error) {
	if c == nil || c.exchange == nil {
		return PresenceUncertain, ErrPresenceUncertain
	}
	return observeAuthoritative(ctx, expected, c.primary, c.queryTimeout, c.exchange)
}

// ObserveChannel performs one bounded direct TCP read through the selected channel.
func (c *PresenceClient) ObserveChannel(ctx context.Context, expected ExpectedTXT, channel ProofChannel) (PresenceState, error) {
	if c == nil || c.exchange == nil {
		return PresenceUncertain, ErrPresenceUncertain
	}
	address := c.primary
	if channel == ProofRecursive {
		address = c.recursive
	} else if channel != ProofAuthoritative {
		return PresenceUncertain, ErrPresenceUncertain
	}
	return observeChannel(ctx, expected, channel, address, c.queryTimeout, c.exchange)
}

// ObserveChannels reads authoritative state followed by recursive state without polling.
func (c *PresenceClient) ObserveChannels(ctx context.Context, expected ExpectedTXT) (PresenceObservation, error) {
	observation := PresenceObservation{Authoritative: PresenceUncertain, Recursive: PresenceUncertain}
	if c == nil || c.exchange == nil || validateExpectedTXT(expected) != nil {
		return observation, ErrPresenceUncertain
	}
	authoritative, err := c.ObserveChannel(ctx, expected, ProofAuthoritative)
	observation.Authoritative = authoritative
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return observation, err
	}
	recursive, recursiveErr := c.ObserveChannel(ctx, expected, ProofRecursive)
	observation.Recursive = recursive
	if errors.Is(recursiveErr, context.Canceled) || errors.Is(recursiveErr, context.DeadlineExceeded) {
		return observation, recursiveErr
	}
	return observation, nil
}

// String prevents generic formatting from exposing configured DNS endpoints.
func (*PresenceClient) String() string { return presenceClientRedacted }

// GoString prevents Go-syntax formatting from exposing configured DNS endpoints.
func (*PresenceClient) GoString() string { return presenceClientRedacted }

// MarshalText prevents text encoders from exposing configured DNS endpoints.
func (*PresenceClient) MarshalText() ([]byte, error) { return []byte(presenceClientRedacted), nil }

// MarshalJSON emits no configured DNS endpoints.
func (*PresenceClient) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// DeleteResult reports the bounded outcome of one exact TXT retirement attempt.
type DeleteResult uint8

const (
	DeleteRemoved DeleteResult = iota + 1
	DeleteAlreadyAbsent
	DeleteResumable
)

// RotationRetirer owns value-aware, rotation-only TXT deletion.
type RotationRetirer struct {
	primary       string
	queryTimeout  time.Duration
	tsigName      string
	tsigFile      string
	tsigAlgorithm string
	exchange      dnsExchange
	loadTSIG      func(string) ([]byte, error)
	observe       func(context.Context, ExpectedTXT) (PresenceState, error)
}

const rotationRetirerRedacted = "<redacted DKIM2 DNS rotation retirer>"

// NewRotationRetirer constructs a value-aware retirer without opening TSIG material.
func NewRotationRetirer(cfg *config.Config) (*RotationRetirer, error) {
	if cfg == nil || strings.TrimSpace(cfg.DNS.PrimaryNameserver) == "" ||
		cfg.DKIM2.DNSQueryTimeoutSeconds < 1 || strings.TrimSpace(cfg.DNS.TSIGKeyName) == "" ||
		strings.TrimSpace(cfg.DNS.TSIGKeyFile) == "" {
		return nil, errors.New("invalid DKIM2 DNS retirement configuration")
	}
	r := &RotationRetirer{
		primary:       cfg.DNS.PrimaryNameserver,
		queryTimeout:  time.Duration(cfg.DKIM2.DNSQueryTimeoutSeconds) * time.Second,
		tsigName:      dns.Fqdn(cfg.DNS.TSIGKeyName),
		tsigFile:      cfg.DNS.TSIGKeyFile,
		tsigAlgorithm: cfg.DNSAlgorithmFQDN(),
		exchange:      exchangeDNS,
		loadTSIG:      readTSIGBytes,
	}
	r.observe = func(ctx context.Context, expected ExpectedTXT) (PresenceState, error) {
		return observeAuthoritative(ctx, expected, r.primary, r.queryTimeout, r.exchange)
	}
	return r, nil
}

// Observe exposes the same read-only authoritative classification used by deletion.
func (r *RotationRetirer) Observe(ctx context.Context, expected ExpectedTXT) (PresenceState, error) {
	if r == nil || r.observe == nil {
		return PresenceUncertain, ErrPresenceUncertain
	}
	return r.observe(ctx, expected)
}

// DeleteExact removes one exact TXT RRset under a value-dependent prerequisite.
func (r *RotationRetirer) DeleteExact(ctx context.Context, zone string, expected ExpectedTXT) (DeleteResult, error) {
	if r == nil || r.observe == nil || r.loadTSIG == nil || r.exchange == nil {
		return 0, ErrDeleteUncertain
	}
	if err := validateZoneOwner(zone, expected); err != nil {
		return 0, errors.New("invalid DKIM2 DNS retirement request")
	}
	state, err := r.observe(ctx, expected)
	if err != nil {
		return 0, mapDeletePresenceError(state, err)
	}
	switch state {
	case PresenceAbsent:
		return DeleteAlreadyAbsent, nil
	case PresenceConflict:
		return 0, ErrDeleteConflict
	case PresenceUncertain:
		return 0, ErrDeleteUncertain
	case PresenceExact:
	default:
		return 0, ErrDeleteUncertain
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	message, err := buildDeleteExactMessage(zone, expected)
	if err != nil {
		return 0, err
	}
	secret, err := r.loadTSIG(r.tsigFile)
	if err != nil {
		return 0, errors.New("load TSIG credential failed")
	}
	defer clear(secret)
	if len(secret) == 0 || r.tsigName == "." {
		return 0, errors.New("complete TSIG configuration is required")
	}
	secretText := string(secret)
	defer func() { secretText = "" }()
	message.SetTsig(r.tsigName, r.tsigAlgorithm, 300, time.Now().Unix())
	client := &dns.Client{
		Net:        "tcp",
		Timeout:    r.queryTimeout,
		TsigSecret: map[string]string{r.tsigName: secretText},
	}
	writeCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	response, exchangeErr := r.exchange(writeCtx, client, message, r.primary)
	cancel()
	client.TsigSecret[r.tsigName] = ""
	client.TsigSecret = nil

	authenticatedResponse := exchangeErr == nil && validateRotationUpdateAuthentication(response, message) == nil
	lostResponse := response == nil
	return r.reconcileDelete(ctx, expected, authenticatedResponse, lostResponse)
}

// reconcileDelete classifies one fresh authoritative readback and never retries a write.
func (r *RotationRetirer) reconcileDelete(ctx context.Context, expected ExpectedTXT, authenticatedResponse, lostResponse bool) (DeleteResult, error) {
	state, err := r.observe(ctx, expected)
	if err != nil {
		return 0, mapDeletePresenceError(state, err)
	}
	switch state {
	case PresenceAbsent:
		if authenticatedResponse || lostResponse {
			return DeleteRemoved, nil
		}
		return 0, ErrDeleteUncertain
	case PresenceExact:
		if !authenticatedResponse && !lostResponse {
			return 0, ErrDeleteUncertain
		}
		return DeleteResumable, ErrDeleteResumable
	case PresenceConflict:
		return 0, ErrDeleteConflict
	default:
		return 0, ErrDeleteUncertain
	}
}

// String prevents generic formatting from exposing endpoints or TSIG metadata.
func (*RotationRetirer) String() string { return rotationRetirerRedacted }

// GoString prevents Go-syntax formatting from exposing endpoints or TSIG metadata.
func (*RotationRetirer) GoString() string { return rotationRetirerRedacted }

// MarshalText prevents text encoders from exposing endpoints or TSIG metadata.
func (*RotationRetirer) MarshalText() ([]byte, error) { return []byte(rotationRetirerRedacted), nil }

// MarshalJSON emits no endpoints or TSIG metadata.
func (*RotationRetirer) MarshalJSON() ([]byte, error) { return json.Marshal(struct{}{}) }

// buildDeleteExactMessage binds a TXT-only RRset deletion to its complete expected value.
func buildDeleteExactMessage(zone string, expected ExpectedTXT) (*dns.Msg, error) {
	if err := validateZoneOwner(zone, expected); err != nil {
		return nil, errors.New("invalid DKIM2 DNS exact-delete request")
	}
	value := &dns.TXT{
		Hdr: dns.RR_Header{Name: expected.Owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: txtChunks(expected.Content),
	}
	message := new(dns.Msg)
	message.SetUpdate(zone)
	message.Used([]dns.RR{value})
	message.RemoveRRset([]dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: expected.Owner, Rrtype: dns.TypeTXT}}})
	return message, nil
}

// observeAuthoritative performs one bounded direct authoritative lookup without recursion or TSIG.
func observeAuthoritative(ctx context.Context, expected ExpectedTXT, primary string, timeout time.Duration, exchange dnsExchange) (PresenceState, error) {
	return observeChannel(ctx, expected, ProofAuthoritative, primary, timeout, exchange)
}

// observeChannel performs one bounded direct read with the channel's exact recursion contract.
func observeChannel(ctx context.Context, expected ExpectedTXT, channel ProofChannel, address string, timeout time.Duration, exchange dnsExchange) (PresenceState, error) {
	if err := validateExpectedTXT(expected); err != nil || strings.TrimSpace(address) == "" || timeout <= 0 || exchange == nil ||
		(channel != ProofAuthoritative && channel != ProofRecursive) {
		return PresenceUncertain, ErrPresenceUncertain
	}
	if err := ctx.Err(); err != nil {
		return PresenceUncertain, err
	}
	query := new(dns.Msg)
	query.SetQuestion(expected.Owner, dns.TypeTXT)
	query.RecursionDesired = channel == ProofRecursive
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := exchange(queryCtx, &dns.Client{Net: "tcp", Timeout: timeout}, query, address)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PresenceUncertain, ctxErr
		}
		if queryErr := queryCtx.Err(); queryErr != nil {
			return PresenceUncertain, queryErr
		}
		return PresenceUncertain, ErrPresenceUncertain
	}
	if response != nil && response.Id != query.Id {
		return PresenceUncertain, ErrPresenceUncertain
	}
	return classifyChannelPresence(response, expected, channel)
}

// classifyObservedPresence maps authoritative evidence into one closed presence state.
func classifyObservedPresence(response *dns.Msg, expected ExpectedTXT) (PresenceState, error) {
	return classifyChannelPresence(response, expected, ProofAuthoritative)
}

// classifyChannelPresence maps one direct response under the selected channel contract.
func classifyChannelPresence(response *dns.Msg, expected ExpectedTXT, channel ProofChannel) (PresenceState, error) {
	if response == nil || !response.Response || response.Truncated ||
		len(response.Question) != 1 || response.Question[0].Name != expected.Owner ||
		response.Question[0].Qtype != dns.TypeTXT || response.Question[0].Qclass != dns.ClassINET {
		return PresenceUncertain, ErrPresenceUncertain
	}
	switch channel {
	case ProofAuthoritative:
		if !response.Authoritative {
			return PresenceUncertain, ErrPresenceUncertain
		}
	case ProofRecursive:
		if response.Authoritative || !response.RecursionAvailable {
			return PresenceUncertain, ErrPresenceUncertain
		}
	default:
		return PresenceUncertain, ErrPresenceUncertain
	}
	if response.Rcode == dns.RcodeNameError {
		if negativeSOA(response, expected) && len(response.Answer) == 0 {
			return PresenceAbsent, nil
		}
		return PresenceUncertain, ErrPresenceUncertain
	}
	if response.Rcode != dns.RcodeSuccess {
		return PresenceUncertain, ErrPresenceUncertain
	}
	if len(response.Answer) == 0 {
		if negativeSOA(response, expected) {
			return PresenceAbsent, nil
		}
		return PresenceUncertain, ErrPresenceUncertain
	}
	if len(response.Ns) != 0 || len(response.Answer) != 1 {
		return PresenceConflict, ErrPresenceConflict
	}
	txt, ok := response.Answer[0].(*dns.TXT)
	if !ok || txt.Hdr.Name != expected.Owner || txt.Hdr.Class != dns.ClassINET ||
		strings.Join(txt.Txt, "") != expected.Content || validateDKIMContent(strings.Join(txt.Txt, "")) != nil {
		return PresenceConflict, ErrPresenceConflict
	}
	return PresenceExact, nil
}

// negativeSOA requires one canonical enclosing SOA as reliable negative evidence.
func negativeSOA(response *dns.Msg, expected ExpectedTXT) bool {
	if len(response.Ns) != 1 {
		return false
	}
	soa, ok := response.Ns[0].(*dns.SOA)
	return ok && soa.Hdr.Class == dns.ClassINET && absoluteCanonicalName(soa.Hdr.Name) &&
		dns.IsSubDomain(soa.Hdr.Name, expected.Owner)
}

// mapDeletePresenceError preserves cancellation while translating closed DNS states.
func mapDeletePresenceError(state PresenceState, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if state == PresenceConflict || errors.Is(err, ErrPresenceConflict) {
		return ErrDeleteConflict
	}
	return fmt.Errorf("%w", ErrDeleteUncertain)
}
