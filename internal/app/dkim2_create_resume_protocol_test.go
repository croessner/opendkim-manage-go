package app

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/miekg/dns"
)

// TestDKIM2CreateResumeAuthenticatedDNSProtocol proves the unchanged updater's real SOA/TCP/TSIG boundary across restart.
func TestDKIM2CreateResumeAuthenticatedDNSProtocol(t *testing.T) {
	manager, repository, random := newCreateResumeHarness(t, "ed25519")
	manager.opts.UpdateDNS = true
	expected := map[string]string{}
	for _, policy := range repository.pending.Policies() {
		if policy.Use() != dkim2model.ProfileUseOrdinaryTransit {
			continue
		}
		for _, credential := range credentialsForProfile(repository.pending, policy.ProfileID()) {
			expected[credential.Selector()+"._domainkey."+policy.SigningDomain()+"."] = dnsRecord(credential)
		}
	}
	const tsigName = "fixture-key."
	const tsigSecret = "c3ludGhldGljLWZpeHR1cmUtc2VjcmV0"
	keyFile := filepath.Join(t.TempDir(), "fixture.key")
	if err := os.WriteFile(keyFile, []byte("Key: "+tsigSecret+"\n"), 0o600); err != nil {
		t.Fatal("cannot write synthetic authentication fixture")
	}
	manager.cfg.DNS.TSIGKeyName, manager.cfg.DNS.TSIGKeyFile = tsigName, keyFile
	var mu sync.Mutex
	updates, invalid := 0, false
	owners := map[string]int{}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		switch {
		case request.Opcode == dns.OpcodeQuery && len(request.Question) == 1 && request.Question[0].Qtype == dns.TypeSOA:
			response.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns: "ns.example.", Mbox: "postmaster.example.", Serial: 1, Refresh: 60, Retry: 60, Expire: 3600, Minttl: 60}}
		case request.Opcode == dns.OpcodeUpdate:
			mu.Lock()
			updates++
			valid := writer.TsigStatus() == nil && request.IsTsig() != nil && request.IsTsig().Hdr.Name == tsigName &&
				len(request.Question) == 1 && len(request.Answer) == 0 && len(request.Ns) == 2
			if valid {
				deleted, inserted := request.Ns[0], request.Ns[1]
				txt, ok := inserted.(*dns.TXT)
				valid = ok && deleted.Header().Rrtype == dns.TypeTXT && deleted.Header().Class == dns.ClassANY &&
					txt.Hdr.Class == dns.ClassINET && deleted.Header().Name == txt.Hdr.Name && expected[txt.Hdr.Name] == strings.Join(txt.Txt, "")
				if valid {
					owners[txt.Hdr.Name]++
				}
			}
			if !valid {
				invalid = true
				response.Rcode = dns.RcodeFormatError
			}
			if updates == 2 {
				response.Rcode = dns.RcodeServerFailure
			}
			mu.Unlock()
		default:
			response.Rcode = dns.RcodeRefused
		}
		if signature := request.IsTsig(); signature != nil {
			response.SetTsig(signature.Hdr.Name, signature.Algorithm, 300, time.Now().Unix())
		}
		if err := writer.WriteMsg(response); err != nil {
			t.Error("isolated DNS fixture response failed")
		}
	})
	manager.cfg.DNS.PrimaryNameserver = startCreateResumeDNSServer(t, handler, tsigName, tsigSecret)
	if _, err := manager.Run(); err == nil {
		t.Fatal("signed DNS failure was reported as successful recovery")
	}
	if repository.observed != repository.pending.Number() || repository.commitCalls != 1 {
		t.Fatal("DNS failure changed the native create commit")
	}
	manager.dns = nil // A fresh updater must reread only its own synthetic authentication file.
	if _, err := manager.Run(); err != nil {
		t.Fatalf("restart with exact stored selector set: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if invalid || updates != 4 || len(owners) != len(expected) || repository.commitCalls != 1 || repository.stageCalls != 0 || random.reads != 0 {
		t.Fatal("authenticated DNS restart violated exact selector scope or no-rekey/no-restage contract")
	}
	for _, count := range owners {
		if count != 2 {
			t.Fatal("DNS restart did not reuse each exact stored record")
		}
	}
}

// startCreateResumeDNSServer serves synthetic SOA and authenticated TXT updates only on isolated loopback sockets.
func startCreateResumeDNSServer(t *testing.T, handler dns.Handler, tsigName, tsigSecret string) string {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("isolated TCP DNS fixture is unavailable")
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal("isolated UDP DNS fixture is unavailable")
	}
	servers := []*dns.Server{{Listener: tcp, Net: "tcp"}, {PacketConn: udp, Net: "udp"}}
	for _, server := range servers {
		started, done := make(chan struct{}), make(chan struct{})
		server.Handler = handler
		server.TsigSecret = map[string]string{tsigName: tsigSecret}
		server.MsgAcceptFunc = func(header dns.Header) dns.MsgAcceptAction {
			opcode := int(header.Bits>>11) & 0xF
			if header.Bits&(1<<15) == 0 && (opcode == dns.OpcodeQuery || opcode == dns.OpcodeUpdate) && header.Qdcount == 1 {
				return dns.MsgAccept
			}
			return dns.MsgReject
		}
		server.NotifyStartedFunc = func() { close(started) }
		go func() { defer close(done); _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown(); <-done })
		select {
		case <-started:
		case <-done:
			t.Fatal("isolated DNS fixture stopped before readiness")
		case <-time.After(5 * time.Second):
			t.Fatal("isolated DNS fixture readiness timed out")
		}
	}
	return tcp.Addr().String()
}
