package dnsupdate

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const testDKIMRecord = "v=DKIM1; k=ed25519; h=sha256; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestBuildCreateIfAbsentUsesNXRRSET(t *testing.T) {
	msg, err := buildCreateIfAbsentMessage("example.test.", "selector._domainkey.example.test.", testDKIMRecord, 300)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(msg.Answer) != 1 || msg.Answer[0].Header().Class != dns.ClassNONE || msg.Answer[0].Header().Rrtype != dns.TypeTXT {
		t.Fatalf("missing NXRRSET prerequisite: %#v", msg.Answer)
	}
	if len(msg.Ns) != 1 || msg.Ns[0].Header().Class != dns.ClassINET {
		t.Fatalf("unexpected update section: %#v", msg.Ns)
	}
}

func TestDNSProofAcceptsEquivalentCanonicalRSAEncodings(t *testing.T) {
	expected, pkcs1Content := rsaDNSCompatibilityRecords(t)
	observed := ExpectedTXT{Owner: expected.Owner, Content: pkcs1Content}
	response := answerFor(observed, true, true)
	if state, err := classifyProofResponse(response, expected, ProofAuthoritative); err != nil || state != ProofExact {
		t.Fatalf("equivalent PKCS#1 proof rejected: state=%v err=%v", state, err)
	}
	if state, err := classifyChannelPresence(response, expected, ProofAuthoritative); err != nil || state != PresenceExact {
		t.Fatalf("equivalent PKCS#1 presence rejected: state=%v err=%v", state, err)
	}
	otherExpected, otherPKCS1Content := rsaDNSCompatibilityRecords(t)
	otherResponse := answerFor(ExpectedTXT{Owner: expected.Owner, Content: otherPKCS1Content}, true, true)
	if otherExpected.Content == expected.Content {
		t.Fatal("independent RSA test keys unexpectedly match")
	}
	if _, err := classifyProofResponse(otherResponse, expected, ProofAuthoritative); err == nil {
		t.Fatal("proof accepted a different RSA key")
	}
}

// rsaDNSCompatibilityRecords returns SPKI publication and equivalent PKCS#1 proof content.
func rsaDNSCompatibilityRecords(t *testing.T) (ExpectedTXT, string) {
	t.Helper()
	pair, err := dkim2model.GenerateRSAKeyPair(dkim2model.DefaultRSABits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	spki := pair.PublicSPKIDER()
	publicAny, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := publicAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T", publicAny)
	}
	owner := "selector._domainkey.example.test."
	prefix := "v=DKIM1; k=rsa; h=sha256; p="
	return ExpectedTXT{Owner: owner, Content: prefix + base64.StdEncoding.EncodeToString(spki)},
		prefix + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(public))
}

func TestClassifyProofResponseRejectsClosedDNSStates(t *testing.T) {
	want := ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}
	good := answerFor(want, true, true)
	if state, err := classifyProofResponse(good, want, ProofAuthoritative); err != nil || state != ProofExact {
		t.Fatalf("good authoritative proof rejected: state=%v err=%v", state, err)
	}
	nodata := emptyAnswer(want.Owner, true, false)
	nodata.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}
	if state, err := classifyProofResponse(nodata, want, ProofAuthoritative); err != nil || state != ProofAbsent {
		t.Fatalf("authoritative NODATA rejected: state=%v err=%v", state, err)
	}
	cases := map[string]*dns.Msg{
		"nil":       nil,
		"truncated": func() *dns.Msg { m := answerFor(want, true, true); m.Truncated = true; return m }(),
		"rcode":     func() *dns.Msg { m := answerFor(want, true, true); m.Rcode = dns.RcodeServerFailure; return m }(),
		"not-aa":    answerFor(want, false, true),
		"wrong-question-class": func() *dns.Msg {
			m := answerFor(want, true, true)
			m.Question[0].Qclass = dns.ClassCHAOS
			return m
		}(),
		"cname": func() *dns.Msg {
			m := answerFor(want, true, true)
			m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: want.Owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "other.example.test."}}
			return m
		}(),
		"multiple": func() *dns.Msg { m := answerFor(want, true, true); m.Answer = append(m.Answer, m.Answer[0]); return m }(),
		"wrong-owner": func() *dns.Msg {
			m := answerFor(want, true, true)
			m.Answer[0].Header().Name = "other.example.test."
			return m
		}(),
		"wrong-key": func() *dns.Msg {
			m := answerFor(want, true, true)
			m.Answer[0].(*dns.TXT).Txt = []string{"v=DKIM1; k=ed25519; h=sha256; p=BBBB"}
			return m
		}(),
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := classifyProofResponse(response, want, ProofAuthoritative); err == nil {
				t.Fatal("closed DNS state accepted")
			}
		})
	}
	recursive := answerFor(want, true, true)
	if _, err := classifyProofResponse(recursive, want, ProofRecursive); err == nil {
		t.Fatal("authoritative response accepted as recursive proof")
	}
}

func TestProofClientUsesDirectTCPChannelsInOrder(t *testing.T) {
	cfg := rotationDNSConfig()
	client, err := NewProofClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	client.exchange = func(ctx context.Context, c *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
		calls = append(calls, address+":"+c.Net+":"+boolText(msg.RecursionDesired))
		want := ExpectedTXT{Owner: msg.Question[0].Name, Content: testDKIMRecord}
		response := answerFor(want, address == cfg.DNS.PrimaryNameserver, address == cfg.DNS.RecursiveNameserver)
		response.Id = msg.Id
		return response, nil
	}
	want := ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}
	if err := client.ProveAll(context.Background(), []ExpectedTXT{want}); err != nil {
		t.Fatalf("prove: %v", err)
	}
	wantCalls := []string{"127.0.0.1:53:tcp:false", "127.0.0.2:53:tcp:true"}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls=%v want=%v", calls, wantCalls)
	}
}

func TestProofClientHonorsCancelAndBoundsPending(t *testing.T) {
	cfg := rotationDNSConfig()
	cfg.DKIM2.ProofMaxAttempts = 2
	client, _ := NewProofClient(cfg)
	calls := 0
	client.exchange = func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error) {
		calls++
		return emptyAnswer("selector._domainkey.example.test.", true, false), nil
	}
	client.wait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.ProveAll(ctx, []ExpectedTXT{{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancel not honored: calls=%d err=%v", calls, err)
	}
}

func TestProofClientBoundsPartialDualPublication(t *testing.T) {
	cfg := rotationDNSConfig()
	cfg.DKIM2.ProofMaxAttempts = 3
	client, _ := NewProofClient(cfg)
	calls := 0
	client.wait = func(context.Context, time.Duration) error { return nil }
	client.exchange = func(_ context.Context, _ *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
		calls++
		owner := msg.Question[0].Name
		if owner == "selector-ed._domainkey.example.test." {
			response := answerFor(ExpectedTXT{Owner: owner, Content: testDKIMRecord}, address == cfg.DNS.PrimaryNameserver, address == cfg.DNS.RecursiveNameserver)
			response.Id = msg.Id
			return response, nil
		}
		response := emptyAnswer(owner, address == cfg.DNS.PrimaryNameserver, address == cfg.DNS.RecursiveNameserver)
		response.Id = msg.Id
		return response, nil
	}
	err := client.ProveAll(context.Background(), []ExpectedTXT{
		{Owner: "selector-ed._domainkey.example.test.", Content: testDKIMRecord},
		{Owner: "selector-rsa._domainkey.example.test.", Content: "v=DKIM1; k=rsa; h=sha256; p=AQAB"},
	})
	if err == nil || calls != 5 {
		t.Fatalf("partial dual proof was not bounded: calls=%d err=%v", calls, err)
	}
}

func TestProofClientRejectsBadEd25519AfterSuccessfulRSAProof(t *testing.T) {
	cfg := rotationDNSConfig()
	client, _ := NewProofClient(cfg)
	calls := 0
	client.exchange = func(_ context.Context, _ *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
		calls++
		content := "v=DKIM1; k=rsa; h=sha256; p=AQAB"
		if msg.Question[0].Name == "ed._domainkey.example.test." {
			content = "v=DKIM1; k=ed25519; h=sha256; p=BBBB"
		}
		response := answerFor(ExpectedTXT{Owner: msg.Question[0].Name, Content: content},
			address == cfg.DNS.PrimaryNameserver, address == cfg.DNS.RecursiveNameserver)
		response.Id = msg.Id
		return response, nil
	}
	err := client.ProveAll(context.Background(), []ExpectedTXT{
		{Owner: "rsa._domainkey.example.test.", Content: "v=DKIM1; k=rsa; h=sha256; p=AQAB"},
		{Owner: "ed._domainkey.example.test.", Content: testDKIMRecord},
	})
	if err == nil || calls != 3 {
		t.Fatalf("bad Ed25519 proof accepted after RSA success: calls=%d err=%v", calls, err)
	}
}

func TestRotationPublisherLoadsTSIGOnlyForWriteAndReconcilesConcurrentCreate(t *testing.T) {
	cfg := rotationDNSConfig()
	cfg.DNS.TSIGKeyName = "synthetic-key"
	cfg.DNS.TSIGKeyFile = "/synthetic/key"
	publisher, err := NewRotationPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loads := 0
	publisher.loadTSIG = func(string) ([]byte, error) { loads++; return []byte("c3ludGhldGlj"), nil }
	lookupCount := 0
	publisher.lookup = func(context.Context, ExpectedTXT) (ProofState, error) {
		lookupCount++
		if lookupCount == 1 {
			return ProofAbsent, nil
		}
		return ProofExact, nil
	}
	publisher.exchange = func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error) {
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeYXRrset}}, nil
	}
	result, err := publisher.PublishIfAbsent(context.Background(), "example.test.", ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord})
	if err != nil || result != PublishAlreadyPresent || loads != 1 {
		t.Fatalf("concurrent resume failed: result=%v loads=%d err=%v", result, loads, err)
	}
}

func TestRotationPublisherExactResumeDoesNotLoadTSIG(t *testing.T) {
	cfg := rotationDNSConfig()
	cfg.DNS.TSIGKeyName, cfg.DNS.TSIGKeyFile = "synthetic-key", "/missing/synthetic-key"
	publisher, _ := NewRotationPublisher(cfg)
	publisher.lookup = func(context.Context, ExpectedTXT) (ProofState, error) { return ProofExact, nil }
	publisher.loadTSIG = func(string) ([]byte, error) { t.Fatal("TSIG opened on exact resume"); return nil, nil }
	result, err := publisher.PublishIfAbsent(context.Background(), "example.test.", ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord})
	if err != nil || result != PublishAlreadyPresent {
		t.Fatalf("resume: result=%v err=%v", result, err)
	}
}

func TestRotationPublisherAcceptsOnlyAuthoritativeNXDOMAINPresenceRead(t *testing.T) {
	cfg := rotationDNSConfig()
	cfg.DNS.TSIGKeyName, cfg.DNS.TSIGKeyFile = "synthetic-key", "/synthetic/key"
	publisher, err := NewRotationPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	publisher.loadTSIG = func(string) ([]byte, error) { return []byte("c3ludGhldGlj"), nil }
	reads := 0
	publisher.exchange = func(_ context.Context, _ *dns.Client, msg *dns.Msg, _ string) (*dns.Msg, error) {
		if msg.Opcode == dns.OpcodeQuery {
			reads++
			if reads == 1 {
				response := new(dns.Msg)
				response.SetReply(msg)
				response.Authoritative = true
				response.Rcode = dns.RcodeNameError
				response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}
				return response, nil
			}
			response := answerFor(ExpectedTXT{Owner: msg.Question[0].Name, Content: testDKIMRecord}, true, false)
			response.Id = msg.Id
			return response, nil
		}
		response := new(dns.Msg)
		response.SetReply(msg)
		response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
		return response, nil
	}
	result, err := publisher.PublishIfAbsent(context.Background(), "example.test.", ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord})
	if err != nil || result != PublishCreated || reads != 2 {
		t.Fatalf("authoritative NXDOMAIN did not continue through NXRRSET: result=%v reads=%d err=%v", result, reads, err)
	}
}

func TestClassifyPresenceNXDOMAINFailsClosed(t *testing.T) {
	want := ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}
	valid := func() *dns.Msg {
		response := new(dns.Msg)
		response.SetQuestion(want.Owner, dns.TypeTXT)
		response.Response = true
		response.Authoritative = true
		response.Rcode = dns.RcodeNameError
		response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}
		return response
	}
	if state, err := classifyPresenceResponse(valid(), want); err != nil || state != ProofAbsent {
		t.Fatalf("valid authoritative NXDOMAIN rejected: state=%v err=%v", state, err)
	}
	cases := map[string]func(*dns.Msg){
		"no-aa":  func(m *dns.Msg) { m.Authoritative = false },
		"no-soa": func(m *dns.Msg) { m.Ns = nil },
		"referral": func(m *dns.Msg) {
			m.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example.test."}}
		},
		"wrong-question":       func(m *dns.Msg) { m.Question[0].Name = "other.example.test." },
		"wrong-question-class": func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			response := valid()
			mutate(response)
			if _, err := classifyPresenceResponse(response, want); err == nil {
				t.Fatal("unsafe NXDOMAIN accepted")
			}
		})
	}
	if _, err := classifyProofResponse(valid(), want, ProofAuthoritative); err == nil {
		t.Fatal("activation proof accepted NXDOMAIN")
	}
}

func TestNewRotationPublisherRequiresCompleteTSIGWithoutOpeningIt(t *testing.T) {
	cfg := rotationDNSConfig()
	if _, err := NewRotationPublisher(cfg); err == nil {
		t.Fatal("publisher accepted missing TSIG configuration")
	}
	cfg.DNS.TSIGKeyName, cfg.DNS.TSIGKeyFile = "synthetic-key", "/missing/synthetic-key"
	if _, err := NewRotationPublisher(cfg); err != nil {
		t.Fatalf("constructor opened TSIG material eagerly: %v", err)
	}
}

func TestRotationPublisherRejectsUnauthenticatedOrUncertainWrites(t *testing.T) {
	cases := map[string]func(*dns.Msg) (*dns.Msg, error){
		"nil": func(*dns.Msg) (*dns.Msg, error) { return nil, nil },
		"unsigned": func(msg *dns.Msg) (*dns.Msg, error) {
			return &dns.Msg{MsgHdr: dns.MsgHdr{Id: msg.Id, Rcode: dns.RcodeSuccess}}, nil
		},
		"bad-tsig": func(*dns.Msg) (*dns.Msg, error) { return nil, errors.New("synthetic authentication failure") },
		"error-rcode": func(msg *dns.Msg) (*dns.Msg, error) {
			return &dns.Msg{MsgHdr: dns.MsgHdr{Id: msg.Id, Rcode: dns.RcodeRefused}}, nil
		},
	}
	for name, exchange := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := rotationDNSConfig()
			cfg.DNS.TSIGKeyName, cfg.DNS.TSIGKeyFile = "synthetic-key", "/synthetic/key"
			publisher, _ := NewRotationPublisher(cfg)
			publisher.lookup = func(context.Context, ExpectedTXT) (ProofState, error) { return ProofAbsent, nil }
			publisher.loadTSIG = func(string) ([]byte, error) { return []byte("c3ludGhldGlj"), nil }
			publisher.exchange = func(ctx context.Context, client *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
				return exchange(msg)
			}
			if _, err := publisher.PublishIfAbsent(context.Background(), "example.test.", ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}); err == nil {
				t.Fatal("unsafe write response accepted")
			}
		})
	}
}

func TestRotationPublisherReconcilesLostWriteResponse(t *testing.T) {
	cases := []struct {
		name       string
		state      ProofState
		readErr    error
		wantResult PublishResult
		wantErr    error
	}{
		{name: "exact is success so far", state: ProofExact, wantResult: PublishAlreadyPresent},
		{name: "absent is explicitly resumable", state: ProofAbsent, wantResult: PublishResumable, wantErr: ErrPublishResumable},
		{name: "different is conflict", readErr: ErrPublishConflict, wantErr: ErrPublishConflict},
		{name: "readback uncertain remains uncertain", readErr: ErrPublishUncertain, wantErr: ErrPublishUncertain},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := rotationDNSConfig()
			cfg.DNS.TSIGKeyName, cfg.DNS.TSIGKeyFile = "synthetic-key", "/synthetic/key"
			publisher, _ := NewRotationPublisher(cfg)
			publisher.loadTSIG = func(string) ([]byte, error) { return []byte("c3ludGhldGlj"), nil }
			reads := 0
			publisher.lookup = func(context.Context, ExpectedTXT) (ProofState, error) {
				reads++
				if reads == 1 {
					return ProofAbsent, nil
				}
				return tt.state, tt.readErr
			}
			writes := 0
			publisher.exchange = func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error) {
				writes++
				return nil, errors.New("synthetic lost response")
			}
			result, err := publisher.PublishIfAbsent(context.Background(), "example.test.", ExpectedTXT{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord})
			if result != tt.wantResult || !errors.Is(err, tt.wantErr) || reads != 2 || writes != 1 {
				t.Fatalf("result=%v err=%v reads=%d writes=%d", result, err, reads, writes)
			}
		})
	}
}

func TestProofClientRejectsAuthoritativeRecursiveDisagreement(t *testing.T) {
	cfg := rotationDNSConfig()
	client, _ := NewProofClient(cfg)
	client.exchange = func(_ context.Context, _ *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
		want := ExpectedTXT{Owner: msg.Question[0].Name, Content: testDKIMRecord}
		response := answerFor(want, address == cfg.DNS.PrimaryNameserver, address == cfg.DNS.RecursiveNameserver)
		response.Id = msg.Id
		if address == cfg.DNS.RecursiveNameserver {
			response.Answer[0].(*dns.TXT).Txt = []string{"v=DKIM1; k=ed25519; h=sha256; p=BBBB"}
		}
		return response, nil
	}
	if err := client.ProveAll(context.Background(), []ExpectedTXT{{Owner: "selector._domainkey.example.test.", Content: testDKIMRecord}}); err == nil {
		t.Fatal("channel disagreement accepted")
	}
}

func TestValidateExpectedTXTAcceptsCanonicalDKIM2ExportWithoutOptionalHashTag(t *testing.T) {
	expected := ExpectedTXT{
		Owner:   "selector._domainkey.example.test.",
		Content: "v=DKIM1; k=ed25519; p=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	}
	if err := ValidateExpectedTXT(expected); err != nil {
		t.Fatalf("canonical DKIM2 export rejected: %v", err)
	}
}

func rotationDNSConfig() *config.Config {
	return &config.Config{DNS: config.DNSConfig{PrimaryNameserver: "127.0.0.1:53", RecursiveNameserver: "127.0.0.2:53", TTL: 300}, DKIM2: config.DKIM2Config{DNSQueryTimeoutSeconds: 5, ProofPollIntervalSeconds: 1, ProofMaxAttempts: 2, RunTimeoutSeconds: 30}}
}

func answerFor(want ExpectedTXT, authoritative, recursionAvailable bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(want.Owner, dns.TypeTXT)
	m.Response = true
	m.Authoritative = authoritative
	m.RecursionAvailable = recursionAvailable
	m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: want.Owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{want.Content}}}
	return m
}

func emptyAnswer(owner string, authoritative, recursionAvailable bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(owner, dns.TypeTXT)
	m.Response = true
	m.Authoritative = authoritative
	m.RecursionAvailable = recursionAvailable
	return m
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
