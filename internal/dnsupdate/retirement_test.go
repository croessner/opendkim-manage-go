package dnsupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBuildDeleteExactUsesValuePrerequisiteAndTXTRRsetDelete(t *testing.T) {
	expected := ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord}
	message, err := buildDeleteExactMessage("example.test.", expected)
	if err != nil {
		t.Fatal(err)
	}
	if message.Opcode != dns.OpcodeUpdate || len(message.Question) != 1 || message.Question[0].Name != "example.test." {
		t.Fatalf("unexpected update envelope: %#v", message)
	}
	if len(message.Answer) != 1 {
		t.Fatalf("prerequisites=%d want=1", len(message.Answer))
	}
	prerequisite, ok := message.Answer[0].(*dns.TXT)
	if !ok || prerequisite.Hdr.Name != expected.Owner || prerequisite.Hdr.Class != dns.ClassINET ||
		prerequisite.Hdr.Ttl != 0 || strings.Join(prerequisite.Txt, "") != expected.Content {
		t.Fatalf("unexpected value prerequisite: %#v", message.Answer)
	}
	if len(message.Ns) != 1 || message.Ns[0].Header().Name != expected.Owner ||
		message.Ns[0].Header().Rrtype != dns.TypeTXT || message.Ns[0].Header().Class != dns.ClassANY {
		t.Fatalf("unexpected delete section: %#v", message.Ns)
	}
}

func TestClassifyObservedPresenceIsClosed(t *testing.T) {
	expected := ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord}
	exact := answerFor(expected, true, false)
	if state, err := classifyObservedPresence(exact, expected); err != nil || state != PresenceExact {
		t.Fatalf("exact rejected: state=%s err=%v", state, err)
	}
	for name, response := range map[string]*dns.Msg{
		"nodata":   authoritativeAbsence(expected.Owner, dns.RcodeSuccess),
		"nxdomain": authoritativeAbsence(expected.Owner, dns.RcodeNameError),
	} {
		t.Run(name, func(t *testing.T) {
			state, err := classifyObservedPresence(response, expected)
			if err != nil || state != PresenceAbsent {
				t.Fatalf("absence rejected: state=%s err=%v", state, err)
			}
		})
	}
	conflicts := map[string]*dns.Msg{
		"different": func() *dns.Msg {
			response := answerFor(expected, true, false)
			response.Answer[0].(*dns.TXT).Txt = []string{"v=DKIM1; k=rsa; h=sha256; p=AQAB"}
			return response
		}(),
		"multiple": func() *dns.Msg {
			response := answerFor(expected, true, false)
			response.Answer = append(response.Answer, response.Answer[0])
			return response
		}(),
		"cname": func() *dns.Msg {
			response := answerFor(expected, true, false)
			response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: expected.Owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "other.example.test."}}
			return response
		}(),
	}
	for name, response := range conflicts {
		t.Run(name, func(t *testing.T) {
			state, err := classifyObservedPresence(response, expected)
			if state != PresenceConflict || !errors.Is(err, ErrPresenceConflict) {
				t.Fatalf("conflict not closed: state=%s err=%v", state, err)
			}
		})
	}
	uncertain := map[string]*dns.Msg{
		"nil": nil,
		"truncated": func() *dns.Msg {
			response := answerFor(expected, true, false)
			response.Truncated = true
			return response
		}(),
		"not-aa": answerFor(expected, false, false),
		"servfail": func() *dns.Msg {
			response := answerFor(expected, true, false)
			response.Rcode = dns.RcodeServerFailure
			return response
		}(),
		"bare-nodata": func() *dns.Msg {
			return emptyAnswer(expected.Owner, true, false)
		}(),
	}
	for name, response := range uncertain {
		t.Run(name, func(t *testing.T) {
			state, err := classifyObservedPresence(response, expected)
			if state != PresenceUncertain || !errors.Is(err, ErrPresenceUncertain) {
				t.Fatalf("uncertain state not closed: state=%s err=%v", state, err)
			}
		})
	}
}

func TestPresenceClientUsesOneDirectAuthoritativeTCPQuery(t *testing.T) {
	client, err := NewPresenceClient(rotationDNSConfig())
	if err != nil {
		t.Fatal(err)
	}
	expected := ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord}
	calls := 0
	client.exchange = func(_ context.Context, dnsClient *dns.Client, query *dns.Msg, address string) (*dns.Msg, error) {
		calls++
		if dnsClient.Net != "tcp" || query.RecursionDesired || query.IsTsig() != nil || address != "127.0.0.1:53" {
			t.Fatalf("observation was not direct read-only TCP")
		}
		response := answerFor(expected, true, false)
		response.Id = query.Id
		return response, nil
	}
	state, err := client.Observe(context.Background(), expected)
	if err != nil || state != PresenceExact || calls != 1 {
		t.Fatalf("state=%s calls=%d err=%v", state, calls, err)
	}
}

func TestPresenceClientObservesBothChannelsWithoutPolling(t *testing.T) {
	expected := ExpectedTXT{Owner: "candidate._domainkey.example.test.", Content: testDKIMRecord}
	tests := []struct {
		name      string
		auth      PresenceState
		recursive PresenceState
		want      PresenceObservation
	}{
		{
			name: "new candidate is authoritative while recursive propagation is pending",
			auth: PresenceExact, recursive: PresenceAbsent,
			want: PresenceObservation{Authoritative: PresenceExact, Recursive: PresenceAbsent},
		},
		{
			name: "old selector is authoritatively absent while recursively cached",
			auth: PresenceAbsent, recursive: PresenceExact,
			want: PresenceObservation{Authoritative: PresenceAbsent, Recursive: PresenceExact},
		},
		{
			name: "old selector expired from both channels",
			auth: PresenceAbsent, recursive: PresenceAbsent,
			want: PresenceObservation{Authoritative: PresenceAbsent, Recursive: PresenceAbsent},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := NewPresenceClient(rotationDNSConfig())
			calls := 0
			client.exchange = func(_ context.Context, dnsClient *dns.Client, query *dns.Msg, address string) (*dns.Msg, error) {
				calls++
				if dnsClient.Net != "tcp" || query.IsTsig() != nil {
					t.Fatal("observation channel was not read-only TCP")
				}
				channelState := test.auth
				authoritative := true
				recursive := false
				if address == "127.0.0.2:53" {
					channelState = test.recursive
					authoritative = false
					recursive = true
					if !query.RecursionDesired {
						t.Fatal("recursive observation omitted RD")
					}
				} else if query.RecursionDesired {
					t.Fatal("authoritative observation set RD")
				}
				var response *dns.Msg
				if channelState == PresenceExact {
					response = answerFor(expected, authoritative, recursive)
				} else {
					response = channelAbsence(expected.Owner, authoritative, recursive, dns.RcodeSuccess)
				}
				response.Id = query.Id
				return response, nil
			}
			observation, err := client.ObserveChannels(context.Background(), expected)
			if err != nil || observation != test.want || calls != 2 {
				t.Fatalf("observation=%s calls=%d err=%v", observation, calls, err)
			}
		})
	}
}

func TestPresenceClientReportsChannelDisagreementAndConflict(t *testing.T) {
	expected := ExpectedTXT{Owner: "candidate._domainkey.example.test.", Content: testDKIMRecord}
	client, _ := NewPresenceClient(rotationDNSConfig())
	client.exchange = func(_ context.Context, _ *dns.Client, query *dns.Msg, address string) (*dns.Msg, error) {
		response := answerFor(expected, address == "127.0.0.1:53", address == "127.0.0.2:53")
		response.Id = query.Id
		if address == "127.0.0.2:53" {
			response.Answer[0].(*dns.TXT).Txt = []string{"v=DKIM1; k=rsa; h=sha256; p=AQAB"}
		}
		return response, nil
	}
	observation, err := client.ObserveChannels(context.Background(), expected)
	if err != nil || observation.Authoritative != PresenceExact || observation.Recursive != PresenceConflict {
		t.Fatalf("observation=%s err=%v", observation, err)
	}
}

func TestRecursivePresenceRequiresStrictDirectNegativeEvidence(t *testing.T) {
	expected := ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord}
	validNXDOMAIN := channelAbsence(expected.Owner, false, true, dns.RcodeNameError)
	if state, err := classifyChannelPresence(validNXDOMAIN, expected, ProofRecursive); err != nil || state != PresenceAbsent {
		t.Fatalf("valid recursive NXDOMAIN rejected: state=%s err=%v", state, err)
	}
	validNODATA := channelAbsence(expected.Owner, false, true, dns.RcodeSuccess)
	if state, err := classifyChannelPresence(validNODATA, expected, ProofRecursive); err != nil || state != PresenceAbsent {
		t.Fatalf("valid recursive NODATA rejected: state=%s err=%v", state, err)
	}
	uncertain := map[string]*dns.Msg{
		"no-ra":     channelAbsence(expected.Owner, false, false, dns.RcodeNameError),
		"aa":        channelAbsence(expected.Owner, true, true, dns.RcodeNameError),
		"no-soa":    emptyAnswer(expected.Owner, false, true),
		"truncated": func() *dns.Msg { response := validNXDOMAIN.Copy(); response.Truncated = true; return response }(),
		"wrong-question": func() *dns.Msg {
			response := validNXDOMAIN.Copy()
			response.Question[0].Name = "other.example.test."
			return response
		}(),
		"wrong-question-class": func() *dns.Msg {
			response := validNXDOMAIN.Copy()
			response.Question[0].Qclass = dns.ClassCHAOS
			return response
		}(),
		"referral": func() *dns.Msg {
			response := emptyAnswer(expected.Owner, false, true)
			response.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example.test."}}
			return response
		}(),
	}
	for name, response := range uncertain {
		t.Run(name, func(t *testing.T) {
			state, err := classifyChannelPresence(response, expected, ProofRecursive)
			if state != PresenceUncertain || !errors.Is(err, ErrPresenceUncertain) {
				t.Fatalf("state=%s err=%v", state, err)
			}
		})
	}
	conflicts := map[string]*dns.Msg{
		"cname": func() *dns.Msg {
			response := answerFor(expected, false, true)
			response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: expected.Owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "other.example.test."}}
			return response
		}(),
		"ambiguous": func() *dns.Msg {
			response := answerFor(expected, false, true)
			response.Answer = append(response.Answer, response.Answer[0])
			return response
		}(),
		"wrong-owner": func() *dns.Msg {
			response := answerFor(expected, false, true)
			response.Answer[0].Header().Name = "other.example.test."
			return response
		}(),
	}
	for name, response := range conflicts {
		t.Run(name, func(t *testing.T) {
			state, err := classifyChannelPresence(response, expected, ProofRecursive)
			if state != PresenceConflict || !errors.Is(err, ErrPresenceConflict) {
				t.Fatalf("state=%s err=%v", state, err)
			}
		})
	}
}

func TestPresenceClientHonorsCancellationWithoutExchange(t *testing.T) {
	client, _ := NewPresenceClient(rotationDNSConfig())
	client.exchange = func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error) {
		t.Fatal("exchange called after cancellation")
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state, err := client.Observe(ctx, ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord})
	if state != PresenceUncertain || !errors.Is(err, context.Canceled) {
		t.Fatalf("state=%s err=%v", state, err)
	}
}

func TestRotationRetirerLoadsTSIGOnlyAfterExactPreReadAndWritesCASOverTCP(t *testing.T) {
	retirer := newTestRetirer(t)
	expected := ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord}
	reads := 0
	loads := 0
	retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) {
		reads++
		if reads == 1 {
			if loads != 0 {
				t.Fatal("TSIG loaded before authoritative pre-read")
			}
			return PresenceExact, nil
		}
		return PresenceAbsent, nil
	}
	retirer.loadTSIG = func(string) ([]byte, error) {
		loads++
		return []byte("c3ludGhldGlj"), nil
	}
	retirer.exchange = func(_ context.Context, client *dns.Client, message *dns.Msg, _ string) (*dns.Msg, error) {
		if client.Net != "tcp" || message.IsTsig() == nil || len(message.Answer) != 1 || len(message.Ns) != 1 {
			t.Fatal("retirement write omitted TCP, TSIG, prerequisite, or delete")
		}
		if message.Ns[0].Header().Class != dns.ClassANY || message.Ns[0].Header().Rrtype != dns.TypeTXT {
			t.Fatal("retirement write is not a TXT-only RRset delete")
		}
		response := new(dns.Msg)
		response.SetReply(message)
		response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
		return response, nil
	}
	result, err := retirer.DeleteExact(context.Background(), "example.test.", expected)
	if err != nil || result != DeleteRemoved || reads != 2 || loads != 1 {
		t.Fatalf("result=%v reads=%d loads=%d err=%v", result, reads, loads, err)
	}
}

func TestRotationRetirerAbsentResumeNeverLoadsTSIGOrRecreates(t *testing.T) {
	retirer := newTestRetirer(t)
	retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) { return PresenceAbsent, nil }
	retirer.loadTSIG = func(string) ([]byte, error) {
		t.Fatal("TSIG loaded for an already absent old RRset")
		return nil, nil
	}
	retirer.exchange = func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error) {
		t.Fatal("write attempted for an already absent old RRset")
		return nil, nil
	}
	result, err := retirer.DeleteExact(context.Background(), "example.test.", ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord})
	if err != nil || result != DeleteAlreadyAbsent {
		t.Fatalf("result=%v err=%v", result, err)
	}
}

func TestRotationRetirerHonorsCancellationBeforeTSIGAccess(t *testing.T) {
	retirer := newTestRetirer(t)
	retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) { return PresenceExact, nil }
	retirer.loadTSIG = func(string) ([]byte, error) {
		t.Fatal("TSIG loaded after cancellation")
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := retirer.DeleteExact(ctx, "example.test.", ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want cancellation", err)
	}
}

func TestRotationRetirerLostResponseClassifiesFreshReadback(t *testing.T) {
	tests := []struct {
		name       string
		state      PresenceState
		stateErr   error
		wantResult DeleteResult
		wantErr    error
	}{
		{name: "absent is success", state: PresenceAbsent, wantResult: DeleteRemoved},
		{name: "exact is explicit resume", state: PresenceExact, wantResult: DeleteResumable, wantErr: ErrDeleteResumable},
		{name: "different is conflict", state: PresenceConflict, stateErr: ErrPresenceConflict, wantErr: ErrDeleteConflict},
		{name: "ambiguous is conflict", state: PresenceConflict, stateErr: ErrPresenceConflict, wantErr: ErrDeleteConflict},
		{name: "uncertain remains uncertain", state: PresenceUncertain, stateErr: ErrPresenceUncertain, wantErr: ErrDeleteUncertain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			retirer := newTestRetirer(t)
			reads := 0
			retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) {
				reads++
				if reads == 1 {
					return PresenceExact, nil
				}
				return test.state, test.stateErr
			}
			retirer.loadTSIG = func(string) ([]byte, error) { return []byte("c3ludGhldGlj"), nil }
			writes := 0
			retirer.exchange = func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, error) {
				writes++
				return nil, errors.New("synthetic lost response")
			}
			result, err := retirer.DeleteExact(context.Background(), "example.test.", ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord})
			if result != test.wantResult || !errors.Is(err, test.wantErr) || reads != 2 || writes != 1 {
				t.Fatalf("result=%v reads=%d writes=%d err=%v", result, reads, writes, err)
			}
		})
	}
}

func TestRotationRetirerUnsignedOrMalformedResponsesFailClosed(t *testing.T) {
	responses := map[string]func(*dns.Msg) (*dns.Msg, error){
		"nil": func(*dns.Msg) (*dns.Msg, error) { return nil, nil },
		"unsigned": func(message *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(message)
			return response, nil
		},
		"truncated": func(message *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(message)
			response.Truncated = true
			response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
			return response, nil
		},
		"bad-rcode": func(message *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(message)
			response.Rcode = dns.RcodeRefused
			response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
			return response, nil
		},
		"bad-id": func(message *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(message)
			response.Id++
			response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
			return response, nil
		},
	}
	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			retirer := newTestRetirer(t)
			reads := 0
			retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) {
				reads++
				if reads == 1 {
					return PresenceExact, nil
				}
				return PresenceAbsent, nil
			}
			retirer.loadTSIG = func(string) ([]byte, error) { return []byte("c3ludGhldGlj"), nil }
			retirer.exchange = func(_ context.Context, _ *dns.Client, message *dns.Msg, _ string) (*dns.Msg, error) {
				return response(message)
			}
			_, err := retirer.DeleteExact(context.Background(), "example.test.", ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord})
			if name == "nil" || name == "bad-rcode" {
				if err != nil {
					t.Fatalf("authenticated or lost response with proven absence was not reconciled: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrDeleteUncertain) {
				t.Fatalf("unsafe response accepted: %v", err)
			}
		})
	}
}

func TestRotationRetirerSignedErrorWithExactReadbackIsResumable(t *testing.T) {
	retirer := newTestRetirer(t)
	reads := 0
	retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) {
		reads++
		return PresenceExact, nil
	}
	retirer.loadTSIG = func(string) ([]byte, error) { return []byte("c3ludGhldGlj"), nil }
	retirer.exchange = func(_ context.Context, _ *dns.Client, message *dns.Msg, _ string) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(message)
		response.Rcode = dns.RcodeYXRrset
		response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
		return response, nil
	}
	result, err := retirer.DeleteExact(context.Background(), "example.test.", ExpectedTXT{Owner: "old._domainkey.example.test.", Content: testDKIMRecord})
	if result != DeleteResumable || !errors.Is(err, ErrDeleteResumable) || reads != 2 {
		t.Fatalf("result=%v reads=%d err=%v", result, reads, err)
	}
}

func TestRotationRetirerSupportsCardinalityNeutralPartialResume(t *testing.T) {
	rsa := ExpectedTXT{Owner: "old-rsa._domainkey.example.test.", Content: "v=DKIM1; k=rsa; h=sha256; p=AQAB"}
	ed25519 := ExpectedTXT{Owner: "old-ed._domainkey.example.test.", Content: testDKIMRecord}
	for name, records := range map[string][]ExpectedTXT{
		"rsa":  {rsa},
		"ed":   {ed25519},
		"dual": {rsa, ed25519},
	} {
		t.Run(name, func(t *testing.T) {
			retirer := newTestRetirer(t)
			states := map[string]PresenceState{rsa.Owner: PresenceExact, ed25519.Owner: PresenceExact}
			if name == "dual" {
				states[rsa.Owner] = PresenceAbsent
			}
			retirer.observe = func(_ context.Context, expected ExpectedTXT) (PresenceState, error) {
				state := states[expected.Owner]
				if state == PresenceExact {
					states[expected.Owner] = PresenceAbsent
				}
				return state, nil
			}
			loads := 0
			retirer.loadTSIG = func(string) ([]byte, error) { loads++; return []byte("c3ludGhldGlj"), nil }
			retirer.exchange = func(_ context.Context, _ *dns.Client, message *dns.Msg, _ string) (*dns.Msg, error) {
				for _, update := range message.Ns {
					if update.Header().Class == dns.ClassINET {
						t.Fatal("resume attempted to recreate an old RRset")
					}
				}
				response := new(dns.Msg)
				response.SetReply(message)
				response.SetTsig("synthetic-key.", dns.HmacSHA256, 300, 0)
				return response, nil
			}
			for _, record := range records {
				if _, err := retirer.DeleteExact(context.Background(), "example.test.", record); err != nil {
					t.Fatal(err)
				}
			}
			if loads != 1 {
				t.Fatalf("loads=%d want=1", loads)
			}
		})
	}
}

func TestRotationDNSObjectsAreRedactedAcrossFormattingAndJSON(t *testing.T) {
	cfg := rotationDNSConfig()
	cfg.DNS.TSIGKeyName = "sensitive-key-name"
	cfg.DNS.TSIGKeyFile = "/sensitive/tsig/path"
	proof, _ := NewProofClient(cfg)
	publisher, _ := NewRotationPublisher(cfg)
	presence, _ := NewPresenceClient(cfg)
	retirer, _ := NewRotationRetirer(cfg)
	expected := ExpectedTXT{Owner: "sensitive._domainkey.private.test.", Content: testDKIMRecord}
	objects := []any{expected, proof, publisher, presence, retirer}
	for _, object := range objects {
		formatted := fmt.Sprintf("%v %#v %s", object, object, object)
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		combined := formatted + string(encoded)
		for _, forbidden := range []string{"private.test", testDKIMRecord, "127.0.0.1", "127.0.0.2", "sensitive-key-name", "/sensitive/tsig/path"} {
			if strings.Contains(combined, forbidden) {
				t.Fatalf("%T leaked %q through formatting or JSON", object, forbidden)
			}
		}
		if string(encoded) != "{}" {
			t.Fatalf("%T JSON=%s want={}", object, encoded)
		}
	}
}

func TestRotationRetirementErrorsDoNotExposeProtectedFacts(t *testing.T) {
	retirer := newTestRetirer(t)
	retirer.observe = func(context.Context, ExpectedTXT) (PresenceState, error) {
		return PresenceConflict, ErrPresenceConflict
	}
	expected := ExpectedTXT{Owner: "secret-selector._domainkey.private.test.", Content: testDKIMRecord}
	_, err := retirer.DeleteExact(context.Background(), "private.test.", expected)
	if !errors.Is(err, ErrDeleteConflict) {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, forbidden := range []string{expected.Owner, expected.Content, "private.test", "synthetic-key", "/synthetic/key"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked protected fact %q", forbidden)
		}
	}
}

func newTestRetirer(t *testing.T) *RotationRetirer {
	t.Helper()
	cfg := rotationDNSConfig()
	cfg.DNS.TSIGKeyName = "synthetic-key"
	cfg.DNS.TSIGKeyFile = "/synthetic/key"
	retirer, err := NewRotationRetirer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return retirer
}

func authoritativeAbsence(owner string, rcode int) *dns.Msg {
	return channelAbsence(owner, true, false, rcode)
}

func channelAbsence(owner string, authoritative, recursive bool, rcode int) *dns.Msg {
	response := emptyAnswer(owner, authoritative, recursive)
	response.Rcode = rcode
	response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}
	return response
}
