package dnsupdate

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

type Client struct {
	cfg       *config.Config
	tsigName  string
	tsigKey   string
	soaLookup func(string) (bool, error)
}

func New(cfg *config.Config) (*Client, error) {
	c := &Client{cfg: cfg}
	if strings.TrimSpace(cfg.DNS.TSIGKeyName) != "" {
		key, err := readTSIGKey(cfg.DNS.TSIGKeyFile)
		if err != nil {
			return nil, err
		}
		c.tsigName = dns.Fqdn(cfg.DNS.TSIGKeyName)
		c.tsigKey = key
	}
	return c, nil
}

func (c *Client) AddDKIMKey(zone, selectorName, content, subdomain string) error {
	var err error
	zone, subdomain, err = c.resolveUpdateTarget(zone, subdomain)
	if err != nil {
		return err
	}
	return c.exchange(buildUpsertMessage(zone, selectorName, content, subdomain, c.cfg.DNS.TTL))
}

func (c *Client) RemoveDKIMKey(zone, selectorName, subdomain string) error {
	var err error
	zone, subdomain, err = c.resolveUpdateTarget(zone, subdomain)
	if err != nil {
		return err
	}
	return c.exchange(buildRemoveMessage(zone, selectorName, subdomain))
}

func (c *Client) ChangeDKIMKey(zone, selectorName, content, subdomain string) error {
	var err error
	zone, subdomain, err = c.resolveUpdateTarget(zone, subdomain)
	if err != nil {
		return err
	}
	return c.exchange(buildUpsertMessage(zone, selectorName, content, subdomain, c.cfg.DNS.TTL))
}

func recordName(zone, selectorName, subdomain string) string {
	rname := selectorName + "._domainkey"
	if subdomain != "" {
		rname += "." + subdomain
	}
	return dns.Fqdn(rname + "." + zone)
}

func txtChunks(content string) []string {
	if content == "" {
		return []string{""}
	}
	chunks := make([]string, 0, (len(content)+253)/254)
	for len(content) > 254 {
		chunks = append(chunks, content[:254])
		content = content[254:]
	}
	return append(chunks, content)
}

func buildUpsertMessage(zone, selectorName, content, subdomain string, ttl int) *dns.Msg {
	fqdn := recordName(zone, selectorName, subdomain)
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
		Txt: txtChunks(content),
	}
	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(zone))
	msg.RemoveRRset([]dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassANY}}})
	msg.Insert([]dns.RR{rr})
	return msg
}

func buildRemoveMessage(zone, selectorName, subdomain string) *dns.Msg {
	fqdn := recordName(zone, selectorName, subdomain)
	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(zone))
	msg.RemoveRRset([]dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassANY}}})
	return msg
}

func (c *Client) resolveUpdateTarget(zone, subdomain string) (string, string, error) {
	zone = strings.Trim(strings.TrimSpace(zone), ".")
	subdomain = strings.Trim(strings.TrimSpace(subdomain), ".")
	if zone == "" {
		return "", "", fmt.Errorf("DNS update zone is empty")
	}
	hasSOA, err := c.hasSOA(zone)
	if err != nil {
		return "", "", err
	}
	if hasSOA {
		return zone, subdomain, nil
	}

	labels := strings.Split(zone, ".")
	for i := 1; i < len(labels)-1; i++ {
		parent := strings.Join(labels[i:], ".")
		hasSOA, err = c.hasSOA(parent)
		if err != nil {
			return "", "", err
		}
		if !hasSOA {
			continue
		}
		prefix := strings.Join(labels[:i], ".")
		if subdomain != "" {
			subdomain = subdomain + "." + prefix
		} else {
			subdomain = prefix
		}
		return parent, subdomain, nil
	}
	return "", "", fmt.Errorf("no SOA-bearing update zone found for %q", zone)
}

func (c *Client) hasSOA(zone string) (bool, error) {
	if c.soaLookup != nil {
		return c.soaLookup(zone)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	server := c.cfg.DNS.PrimaryNameserver
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return false, fmt.Errorf("SOA lookup for %q failed: %w", zone, err)
	}
	if resp == nil {
		return false, fmt.Errorf("SOA lookup for %q returned no response", zone)
	}
	if resp.Rcode == dns.RcodeNameError {
		return false, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false, fmt.Errorf("SOA lookup for %q failed with rcode=%s", zone, dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) exchange(msg *dns.Msg) error {
	if c.tsigName != "" {
		msg.SetTsig(c.tsigName, c.cfg.DNSAlgorithmFQDN(), 300, time.Now().Unix())
	}
	server := c.cfg.DNS.PrimaryNameserver
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	var tsigSecret map[string]string
	if c.tsigName != "" {
		tsigSecret = map[string]string{c.tsigName: c.tsigKey}
	}
	client := &dns.Client{Net: "tcp", TsigSecret: tsigSecret}
	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return fmt.Errorf("dns exchange failed: %w", err)
	}
	return validateUpdateResponse(resp, c.tsigName != "")
}

func validateUpdateResponse(resp *dns.Msg, requireTSIG bool) error {
	if resp == nil {
		return fmt.Errorf("dns exchange returned no response")
	}
	if requireTSIG && resp.IsTsig() == nil {
		return fmt.Errorf("dns update response is missing TSIG authentication")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns update failed with rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	return nil
}

func readTSIGKey(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("dns.tsig_key_file is required when tsig_key_name is set")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open TSIG key file: %w", err)
	}
	s := bufio.NewScanner(f)
	key := ""
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Key:") {
			key = strings.TrimSpace(strings.TrimPrefix(line, "Key:"))
			break
		}
	}
	scanErr := s.Err()
	closeErr := f.Close()
	if scanErr != nil || closeErr != nil {
		var errs []error
		if scanErr != nil {
			errs = append(errs, fmt.Errorf("read TSIG key file: %w", scanErr))
		}
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("close TSIG key file: %w", closeErr))
		}
		return "", errors.Join(errs...)
	}
	if key == "" {
		return "", fmt.Errorf("TSIG key file format error (missing 'Key:' line)")
	}
	return key, nil
}

func Make254(arg string) string {
	chunks := txtChunks(arg)
	quoted := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		quoted = append(quoted, fmt.Sprintf("%q", chunk))
	}
	return strings.Join(quoted, " ")
}
