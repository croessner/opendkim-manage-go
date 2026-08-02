package dnsupdate

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

const (
	protocolTSIGName   = "rotation-key.example.test."
	protocolTSIGSecret = "c3ludGhldGljLXRlc3Qtb25seS10c2lnLXNlY3JldA=="
)

// TestRotationDNSProtocolHarness exercises real local TCP DNS messages and
// TSIG authentication. It proves only the isolated protocol contract, not
// global propagation, deployment, or production runtime activation.
func TestRotationDNSProtocolHarness(t *testing.T) {
	zone := newProtocolZone("example.test.")
	zone.put(&dns.A{Hdr: dns.RR_Header{Name: "rsa._domainkey.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 10)})
	authoritative := startProtocolDNSServer(t, zone, true, false)
	recursive := startProtocolDNSServer(t, zone, false, true)

	cfg := &config.Config{
		DNS: config.DNSConfig{
			PrimaryNameserver: authoritative, RecursiveNameserver: recursive,
			TSIGKeyName: protocolTSIGName, TSIGKeyFile: "synthetic-test-only.key",
			Algorithm: "hmac_sha256", TTL: 300,
		},
		DKIM2: config.DKIM2Config{
			DNSQueryTimeoutSeconds: 2, ProofPollIntervalSeconds: 1,
			ProofMaxAttempts: 1, RunTimeoutSeconds: 5,
		},
	}
	publisher, err := NewRotationPublisher(cfg)
	if err != nil {
		t.Fatalf("publisher: %v", err)
	}
	loads := 0
	publisher.loadTSIG = func(path string) ([]byte, error) {
		loads++
		if path != "synthetic-test-only.key" {
			return nil, errors.New("unexpected synthetic path")
		}
		return []byte(protocolTSIGSecret), nil
	}

	rsa := ExpectedTXT{Owner: "rsa._domainkey.example.test.", Content: "v=DKIM1; k=rsa; h=sha256; p=AQIDBA=="}
	ed := ExpectedTXT{Owner: "ed._domainkey.example.test.", Content: testDKIMRecord}
	createMessage, err := buildCreateIfAbsentMessage("example.test.", rsa.Owner, rsa.Content, 300)
	if err != nil {
		t.Fatal(err)
	}
	prerequisite, ok := createMessage.Answer[0].(*dns.ANY)
	if !ok || prerequisite.Hdr.Rrtype != dns.TypeTXT || prerequisite.Hdr.Class != dns.ClassNONE {
		t.Fatal("NXRRSET was not encoded as a TXT-typed NONE-class dns.ANY prerequisite")
	}
	result, err := publisher.PublishIfAbsent(context.Background(), "example.test.", rsa)
	if err != nil || result != PublishCreated {
		t.Fatalf("first NXRRSET publication = %v, %v", result, err)
	}
	if loads != 1 || zone.updateCount() != 1 {
		t.Fatalf("TSIG loads=%d updates=%d", loads, zone.updateCount())
	}
	if !zone.hasType(rsa.Owner, dns.TypeA) || !zone.hasExactTXT(rsa) {
		t.Fatal("TXT insertion did not preserve the unrelated A record")
	}

	// Simulate a restart after only the first credential of a dual binding was published.
	resumed, err := NewRotationPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resumed.loadTSIG = func(string) ([]byte, error) {
		loads++
		return []byte(protocolTSIGSecret), nil
	}
	if result, err = resumed.PublishIfAbsent(context.Background(), "example.test.", rsa); err != nil || result != PublishAlreadyPresent {
		t.Fatalf("resume existing = %v, %v", result, err)
	}
	if loads != 1 || zone.updateCount() != 1 {
		t.Fatal("exact resume accessed TSIG or rewrote the existing RRset")
	}
	if result, err = resumed.PublishIfAbsent(context.Background(), "example.test.", ed); err != nil || result != PublishCreated {
		t.Fatalf("resume missing credential = %v, %v", result, err)
	}
	if loads != 2 || zone.updateCount() != 2 || !zone.hasExactTXT(ed) {
		t.Fatal("partial dual resume did not publish exactly the missing RRset")
	}

	proof, err := NewProofClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.ProveAll(context.Background(), []ExpectedTXT{rsa, ed}); err != nil {
		t.Fatalf("authoritative and recursive proof: %v", err)
	}

	conflict := ExpectedTXT{Owner: rsa.Owner, Content: "v=DKIM1; k=rsa; h=sha256; p=BAUGBw=="}
	before := zone.updateCount()
	if _, err := resumed.PublishIfAbsent(context.Background(), "example.test.", conflict); !errors.Is(err, ErrPublishConflict) {
		t.Fatalf("conflicting overwrite error = %v", err)
	}
	if zone.updateCount() != before || !zone.hasExactTXT(rsa) {
		t.Fatal("conflicting publication overwrote the established RRset")
	}
}

type protocolZone struct {
	mu      sync.RWMutex
	origin  string
	records map[string][]dns.RR
	updates int
}

func newProtocolZone(origin string) *protocolZone {
	return &protocolZone{origin: origin, records: make(map[string][]dns.RR)}
}

func (z *protocolZone) put(record dns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	owner := record.Header().Name
	z.records[owner] = append(z.records[owner], dns.Copy(record))
}

func (z *protocolZone) updateCount() int {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.updates
}

func (z *protocolZone) hasType(owner string, recordType uint16) bool {
	z.mu.RLock()
	defer z.mu.RUnlock()
	for _, record := range z.records[owner] {
		if record.Header().Rrtype == recordType {
			return true
		}
	}
	return false
}

func (z *protocolZone) hasExactTXT(expected ExpectedTXT) bool {
	z.mu.RLock()
	defer z.mu.RUnlock()
	for _, record := range z.records[expected.Owner] {
		if txt, ok := record.(*dns.TXT); ok && len(txt.Txt) > 0 && joinTXT(txt.Txt) == expected.Content {
			return true
		}
	}
	return false
}

func (z *protocolZone) serve(authoritative, recursive bool) dns.HandlerFunc {
	return func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = authoritative
		response.RecursionAvailable = recursive
		switch request.Opcode {
		case dns.OpcodeQuery:
			z.answerQuery(response, request)
		case dns.OpcodeUpdate:
			z.answerUpdate(writer, response, request)
		default:
			response.Rcode = dns.RcodeNotImplemented
		}
		if requestTSIG := request.IsTsig(); requestTSIG != nil {
			response.SetTsig(requestTSIG.Hdr.Name, requestTSIG.Algorithm, 300, time.Now().Unix())
		}
		_ = writer.WriteMsg(response)
	}
}

func (z *protocolZone) answerQuery(response, request *dns.Msg) {
	if len(request.Question) != 1 || request.Question[0].Qtype != dns.TypeTXT || request.Question[0].Qclass != dns.ClassINET {
		response.Rcode = dns.RcodeFormatError
		return
	}
	z.mu.RLock()
	defer z.mu.RUnlock()
	owner := request.Question[0].Name
	ownerExists := len(z.records[owner]) > 0
	for _, record := range z.records[owner] {
		if record.Header().Rrtype == dns.TypeTXT {
			response.Answer = append(response.Answer, dns.Copy(record))
		}
	}
	if len(response.Answer) == 0 {
		if !ownerExists {
			response.Rcode = dns.RcodeNameError
		}
		response.Ns = []dns.RR{protocolSOA(z.origin)}
	}
}

func (z *protocolZone) answerUpdate(writer dns.ResponseWriter, response, request *dns.Msg) {
	if writer.TsigStatus() != nil || request.IsTsig() == nil || len(request.Question) != 1 || request.Question[0].Name != z.origin ||
		len(request.Answer) != 1 || len(request.Ns) != 1 {
		response.Rcode = dns.RcodeRefused
		return
	}
	prerequisite := request.Answer[0]
	insert, insertOK := request.Ns[0].(*dns.TXT)
	if !insertOK {
		response.Rcode = dns.RcodeFormatError
		return
	}
	if prerequisite.Header().Class != dns.ClassNONE || prerequisite.Header().Rrtype != dns.TypeTXT ||
		prerequisite.Header().Ttl != 0 || prerequisite.Header().Rdlength != 0 ||
		insert.Hdr.Class != dns.ClassINET || prerequisite.Header().Name != insert.Hdr.Name {
		response.Rcode = dns.RcodeFormatError
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, record := range z.records[insert.Hdr.Name] {
		if record.Header().Rrtype == dns.TypeTXT {
			response.Rcode = dns.RcodeYXRrset
			return
		}
	}
	z.records[insert.Hdr.Name] = append(z.records[insert.Hdr.Name], dns.Copy(insert))
	z.updates++
}

func startProtocolDNSServer(t *testing.T, zone *protocolZone, authoritative, recursive bool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local TCP DNS harness unavailable: %v", err)
	}
	server := &dns.Server{
		Listener: listener, Net: "tcp", Handler: zone.serve(authoritative, recursive),
		TsigSecret:    map[string]string{protocolTSIGName: protocolTSIGSecret},
		MsgAcceptFunc: acceptProtocolMessage,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})
	return listener.Addr().String()
}

func acceptProtocolMessage(header dns.Header) dns.MsgAcceptAction {
	opcode := int(header.Bits>>11) & 0xF
	if opcode == dns.OpcodeQuery {
		return dns.DefaultMsgAcceptFunc(header)
	}
	if opcode == dns.OpcodeUpdate && header.Bits&(1<<15) == 0 && header.Qdcount == 1 &&
		header.Ancount == 1 && header.Nscount == 1 && header.Arcount <= 1 {
		return dns.MsgAccept
	}
	return dns.MsgReject
}

func protocolSOA(origin string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns1." + origin, Mbox: "hostmaster." + origin, Serial: 1,
		Refresh: 60, Retry: 60, Expire: 300, Minttl: 60,
	}
}

func joinTXT(chunks []string) string {
	result := ""
	for _, chunk := range chunks {
		result += chunk
	}
	return result
}
