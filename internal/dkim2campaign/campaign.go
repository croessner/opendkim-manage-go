// Package dkim2campaign owns the narrow external DKIM2 campaign automation adapter.
package dkim2campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

const (
	maxReportBytes   = 4096
	maxArtifactBytes = 1 << 20
	maxArtifactRRs   = 4096
	reportSchema     = "dkim2-rotation-report-v1"
	exportSchema     = "; dkim2-dns-export-v1"
)

var errCampaign = errors.New("DKIM2 global campaign is unavailable or incomplete")

// Outcome is one closed scheduler-facing global campaign result.
type Outcome string

const (
	OutcomeActivated Outcome = "activated"
	OutcomeDryRun    Outcome = "dry-run"
	OutcomePending   Outcome = "pending"
	OutcomeIdle      Outcome = "idle"
)

// Runner invokes the protected DKIM2 command without exposing provider errors.
type Runner interface {
	Run(context.Context, []string) ([]byte, error)
}

// RunnerFunc adapts a function to Runner for bounded tests and integrations.
type RunnerFunc func(context.Context, []string) ([]byte, error)

// Run invokes the wrapped campaign command.
func (f RunnerFunc) Run(ctx context.Context, arguments []string) ([]byte, error) {
	return f(ctx, arguments)
}

// Publisher owns collision-safe authenticated DNS publication.
type Publisher interface {
	PublishIfAbsent(context.Context, string, dnsupdate.ExpectedTXT) (dnsupdate.PublishResult, error)
}

// Controller serializes one complete global campaign invocation.
type Controller struct {
	configuration config.DKIM2CampaignConfig
	directory     *protectedDirectory
	runner        Runner
	publisher     Publisher
	rotationAfter time.Duration
	now           func() time.Time
}

// New constructs the global adapter from separately scoped command and DNS authorities.
func New(configuration config.DKIM2CampaignConfig, rotateAfterDays int, runner Runner, publisher Publisher) (*Controller, error) {
	if !configuration.Enabled || runner == nil || publisher == nil || configuration.MaxBatches < 1 || configuration.MaxBatches > 1024 ||
		rotateAfterDays < 1 || rotateAfterDays > 36500 ||
		!filepath.IsAbs(configuration.ConfigFile) || !filepath.IsAbs(configuration.JournalFile) || !filepath.IsAbs(configuration.ArtifactDirectory) ||
		filepath.Dir(configuration.JournalFile) != configuration.ArtifactDirectory || filepath.Dir(configuration.CadenceFile) != configuration.ArtifactDirectory {
		return nil, errCampaign
	}
	directory, err := openProtectedDirectory(configuration.ArtifactDirectory)
	if err != nil {
		return nil, errCampaign
	}
	return &Controller{configuration: configuration, directory: directory, runner: runner, publisher: publisher,
		rotationAfter: time.Duration(rotateAfterDays) * 24 * time.Hour, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Close releases the descriptor that anchors every protected campaign artifact operation.
func (c *Controller) Close() error {
	if c == nil || c.directory == nil {
		return nil
	}
	return c.directory.close()
}

// Run starts or resumes one campaign, publishes every available batch, and accepts only exact activation.
func (c *Controller) Run(ctx context.Context, dryRun bool) (Outcome, error) { //nolint:gocyclo // The serial protocol keeps every recovery edge explicit.
	if c == nil || ctx == nil || ctx.Err() != nil {
		return "", errCampaign
	}
	if dryRun {
		report, err := c.invoke(ctx, "run", "--config", c.configuration.ConfigFile, "--journal", c.configuration.JournalFile, "--automatic", "--dry-run", "--machine")
		if err != nil || report.Command != "run" || report.State != "planned" || report.Result != "dry_run" {
			return "", errCampaign
		}
		return OutcomeDryRun, nil
	}
	now := c.now()
	if now.IsZero() || now.Location() != time.UTC {
		return "", errCampaign
	}
	journalPresent, err := c.directory.regularPresent(filepath.Base(c.configuration.JournalFile), maxArtifactBytes)
	if err != nil {
		return "", errCampaign
	}
	if !journalPresent {
		due, dueErr := c.due(now)
		if dueErr != nil {
			return "", errCampaign
		}
		if !due {
			return OutcomeIdle, nil
		}
	}

	report, runErr := c.invoke(ctx, "run", "--config", c.configuration.ConfigFile, "--journal", c.configuration.JournalFile, "--automatic", "--apply", "--machine")
	if runErr == nil && report.activated() {
		if err := c.complete(now); err != nil {
			return "", errCampaign
		}
		return OutcomeActivated, nil
	}
	status, statusErr := c.invoke(ctx, "status", "--config", c.configuration.ConfigFile, "--journal", c.configuration.JournalFile, "--machine")
	if statusErr != nil || status.Command != "status" {
		return OutcomePending, errCampaign
	}
	if status.activated() {
		if err := c.complete(now); err != nil {
			return "", errCampaign
		}
		return OutcomeActivated, nil
	}
	if !status.resumable() {
		return OutcomePending, errCampaign
	}

	for batch := 1; batch <= c.configuration.MaxBatches; batch++ {
		path := c.artifactPath(batch)
		exported, exportErr := c.invoke(ctx, "dns-export", "--config", c.configuration.ConfigFile, "--journal", c.configuration.JournalFile,
			"--output", path, "--batch", strconv.Itoa(batch), "--machine")
		if exportErr != nil {
			break
		}
		if exported.Command != "dns-export" || exported.Result != "success" {
			return OutcomePending, errCampaign
		}
		records, readErr := readArtifact(c.directory, filepath.Base(path))
		if readErr != nil {
			return OutcomePending, errCampaign
		}
		for _, record := range records {
			zone, zoneErr := recordZone(record.Owner)
			if zoneErr != nil {
				return OutcomePending, errCampaign
			}
			if _, publishErr := c.publisher.PublishIfAbsent(ctx, zone, record); publishErr != nil {
				return OutcomePending, errCampaign
			}
		}
	}

	final, finalErr := c.invoke(ctx, "run", "--config", c.configuration.ConfigFile, "--journal", c.configuration.JournalFile, "--automatic", "--apply", "--machine")
	if finalErr != nil || !final.activated() {
		return OutcomePending, errCampaign
	}
	if err := c.complete(now); err != nil {
		return "", errCampaign
	}
	return OutcomeActivated, nil
}

func (c *Controller) due(now time.Time) (bool, error) {
	document, exists, err := c.directory.readRegular(filepath.Base(c.configuration.CadenceFile), 256)
	if err != nil {
		return false, errCampaign
	}
	defer clear(document)
	if !exists {
		return true, nil
	}
	var state struct {
		Schema            string `json:"schema"`
		LastActivatedUnix int64  `json:"last_activated_unix"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || state.Schema != "opendkim-manage-dkim2-cadence-v1" || state.LastActivatedUnix <= 0 {
		return false, errCampaign
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errCampaign
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(document, append(canonical, '\n')) {
		return false, errCampaign
	}
	last := time.Unix(state.LastActivatedUnix, 0).UTC()
	if last.After(now) {
		return false, errCampaign
	}
	return now.Sub(last) >= c.rotationAfter, nil
}

func (c *Controller) complete(now time.Time) error {
	state := struct {
		Schema            string `json:"schema"`
		LastActivatedUnix int64  `json:"last_activated_unix"`
	}{"opendkim-manage-dkim2-cadence-v1", now.Unix()}
	document, err := json.Marshal(state)
	if err != nil {
		return errCampaign
	}
	document = append(document, '\n')
	if err := c.directory.replace(filepath.Base(c.configuration.CadenceFile), document); err != nil {
		clear(document)
		return errCampaign
	}
	clear(document)
	return c.cleanupCompleted()
}

func (c *Controller) invoke(ctx context.Context, command string, arguments ...string) (machineReport, error) {
	full := append([]string{"datasource", "rotation", command}, arguments...)
	document, runErr := c.runner.Run(ctx, full)
	report, parseErr := parseMachineReport(document)
	clear(document)
	if runErr != nil || parseErr != nil {
		return machineReport{}, errCampaign
	}
	return report, nil
}

func (c *Controller) artifactPath(batch int) string {
	return filepath.Join(c.configuration.ArtifactDirectory, fmt.Sprintf("campaign-dns-%04d.zone", batch))
}

// cleanupCompleted removes only exact configured transient files after activation proof.
func (c *Controller) cleanupCompleted() error {
	for batch := 1; batch <= c.configuration.MaxBatches; batch++ {
		if err := c.directory.removeRegularIfPresent(filepath.Base(c.artifactPath(batch)), maxArtifactBytes); err != nil {
			return err
		}
	}
	return c.directory.removeRegularIfPresent(filepath.Base(c.configuration.JournalFile), maxArtifactBytes)
}

type machineReport struct {
	Schema          string `json:"schema"`
	Command         string `json:"command"`
	Mode            string `json:"mode,omitempty"`
	State           string `json:"state,omitempty"`
	Backend         string `json:"backend"`
	WorkCount       uint32 `json:"work_count"`
	RecordCount     uint32 `json:"record_count"`
	BatchCount      uint32 `json:"batch_count"`
	RetainedCount   uint32 `json:"retained_count"`
	UnresolvedCount uint32 `json:"unresolved_count"`
	Result          string `json:"result"`
}

func parseMachineReport(document []byte) (machineReport, error) {
	if len(document) == 0 || len(document) > maxReportBytes || document[len(document)-1] != '\n' {
		return machineReport{}, errCampaign
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var report machineReport
	if err := decoder.Decode(&report); err != nil {
		return machineReport{}, errCampaign
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return machineReport{}, errCampaign
	}
	canonical, err := json.Marshal(report)
	if err != nil || !bytes.Equal(document, append(canonical, '\n')) || !report.valid() {
		return machineReport{}, errCampaign
	}
	return report, nil
}

func (r machineReport) valid() bool {
	if r.Schema != reportSchema || r.Command == "" || r.Backend == "" || r.Result == "" || r.Mode != "normal" {
		return false
	}
	if !oneOf(r.Command, "run", "status", "dns-export") || !oneOf(r.Backend, "ldap", "postgresql", "mysql", "mariadb") ||
		!oneOf(r.State, "planned", "staged", "dns_in_progress", "dns_complete", "activating", "activated", "reconcile_required") ||
		!oneOf(r.Result, "success", "dry_run", "in_progress", "reconcile_required") {
		return false
	}
	return r.WorkCount <= 131072 && r.RecordCount <= 262144 && r.BatchCount <= 1024
}

func (r machineReport) activated() bool { return r.State == "activated" && r.Result == "success" }

func (r machineReport) resumable() bool {
	return oneOf(r.State, "staged", "dns_in_progress", "dns_complete", "activating") && r.Result != "reconcile_required"
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func readArtifact(directory *protectedDirectory, name string) ([]dnsupdate.ExpectedTXT, error) {
	document, exists, err := directory.readRegular(name, maxArtifactBytes)
	if err != nil || !exists {
		return nil, errCampaign
	}
	defer clear(document)
	lines := strings.Split(string(document), "\n")
	if len(lines) < 5 || lines[0] != exportSchema || !strings.HasPrefix(lines[1], "; ttl-seconds=") || lines[len(lines)-1] != "" {
		return nil, errCampaign
	}
	ttl, err := strconv.ParseUint(strings.TrimPrefix(lines[1], "; ttl-seconds="), 10, 32)
	if err != nil || ttl == 0 || ttl > 604800 {
		return nil, errCampaign
	}
	records := make([]dnsupdate.ExpectedTXT, 0, (len(lines)-2)/2)
	seen := make(map[string]struct{})
	for index := 2; index < len(lines)-1; index += 2 {
		if index+1 >= len(lines)-1 || !strings.HasPrefix(lines[index], "; algorithm=") || !strings.Contains(lines[index], " selector=") {
			return nil, errCampaign
		}
		metadata := strings.Fields(strings.TrimPrefix(lines[index], "; "))
		if len(metadata) != 2 || !strings.HasPrefix(metadata[0], "algorithm=") || !strings.HasPrefix(metadata[1], "selector=") {
			return nil, errCampaign
		}
		algorithm := strings.TrimPrefix(metadata[0], "algorithm=")
		selector := strings.TrimPrefix(metadata[1], "selector=")
		_, selectorOK := dns.IsDomainName(selector)
		if !oneOf(algorithm, "rsa-sha256", "ed25519-sha256") || selector == "" || strings.ToLower(selector) != selector || !selectorOK || dns.IsFqdn(selector) {
			return nil, errCampaign
		}
		rr, parseErr := dns.NewRR(lines[index+1])
		txt, ok := rr.(*dns.TXT)
		if parseErr != nil || !ok || txt.Hdr.Rrtype != dns.TypeTXT || uint64(txt.Hdr.Ttl) != ttl || !dns.IsFqdn(txt.Hdr.Name) {
			return nil, errCampaign
		}
		content := strings.Join(txt.Txt, "")
		if !strings.HasPrefix(content, "v=DKIM1; k=") || !strings.Contains(content, "; p=") {
			return nil, errCampaign
		}
		wantKeyType := "k=ed25519"
		if algorithm == "rsa-sha256" {
			wantKeyType = "k=rsa"
		}
		if !strings.HasPrefix(txt.Hdr.Name, selector+"._domainkey.") || !strings.Contains(content, wantKeyType) {
			return nil, errCampaign
		}
		if _, duplicate := seen[txt.Hdr.Name]; duplicate {
			return nil, errCampaign
		}
		seen[txt.Hdr.Name] = struct{}{}
		expected := dnsupdate.ExpectedTXT{Owner: txt.Hdr.Name, Content: content}
		if dnsupdate.ValidateExpectedTXT(expected) != nil {
			return nil, errCampaign
		}
		records = append(records, expected)
		if len(records) > maxArtifactRRs {
			return nil, errCampaign
		}
	}
	if len(records) == 0 {
		return nil, errCampaign
	}
	return records, nil
}

func recordZone(owner string) (string, error) {
	const marker = "._domainkey."
	index := strings.Index(owner, marker)
	if index <= 0 || strings.Count(owner, marker) != 1 {
		return "", errCampaign
	}
	zone := owner[index+len(marker):]
	if _, ok := dns.IsDomainName(zone); !ok || !dns.IsFqdn(zone) || strings.ToLower(zone) != zone {
		return "", errCampaign
	}
	return zone, nil
}

// OSRunner executes one exact sibling dkim2d binary with bounded output and no inherited input.
type OSRunner struct{ executable string }

// NewOSRunner constructs a runner for one canonical absolute executable path.
func NewOSRunner(executable string) (*OSRunner, error) {
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return nil, errCampaign
	}
	return &OSRunner{executable: executable}, nil
}

// Run invokes the command while suppressing potentially sensitive stderr.
func (r *OSRunner) Run(ctx context.Context, arguments []string) ([]byte, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || len(arguments) == 0 {
		return nil, errCampaign
	}
	var stdout boundedBuffer
	command := exec.CommandContext(ctx, r.executable, arguments...)
	command.Stdin, command.Stdout, command.Stderr = nil, &stdout, io.Discard
	err := command.Run()
	if stdout.overflow {
		clear(stdout.data)
		return nil, errCampaign
	}
	return stdout.data, err
}

type boundedBuffer struct {
	data     []byte
	overflow bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(b.data)+len(value) > maxReportBytes {
		b.overflow = true
		return len(value), nil
	}
	b.data = append(b.data, value...)
	return len(value), nil
}
