package dkim2campaign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dnsupdate"
)

type fakePublisher struct{ records []dnsupdate.ExpectedTXT }

func (f *fakePublisher) PublishIfAbsent(_ context.Context, _ string, record dnsupdate.ExpectedTXT) (dnsupdate.PublishResult, error) {
	f.records = append(f.records, record)
	return dnsupdate.PublishCreated, nil
}

type scriptedRunner struct {
	t       *testing.T
	state   string
	journal string
	calls   [][]string
}

func (s *scriptedRunner) Run(_ context.Context, arguments []string) ([]byte, error) {
	s.calls = append(s.calls, append([]string(nil), arguments...))
	command := arguments[2]
	switch command {
	case "run":
		if s.state == "" {
			s.state = "staged"
			if err := os.WriteFile(s.journal, []byte("protected"), 0o600); err != nil {
				s.t.Fatal(err)
			}
			return nil, errors.New("dns proof pending")
		}
		s.state = "activated"
		return reportBytes("run", "activated", 2, 4, 2, "success"), nil
	case "status":
		return reportBytes("status", s.state, 2, 4, 0, "success"), nil
	case "dns-export":
		batch := argumentValue(arguments, "--batch")
		path := argumentValue(arguments, "--output")
		switch batch {
		case "1":
			writeDNSArtifact(s.t, path, "a._domainkey.example.test.", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
		case "2":
			writeDNSArtifact(s.t, path, "b._domainkey.other.example.", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=")
		default:
			return nil, errors.New("batch unavailable")
		}
		return reportBytes("dns-export", "staged", 2, 4, 0, "success"), nil
	default:
		s.t.Fatalf("unexpected command: %v", arguments)
		return nil, errors.New("unexpected")
	}
}

func TestControllerRotatesOneCompleteMultiBatchCampaign(t *testing.T) {
	directory := protectedTempDir(t)
	configuration := testCampaignConfig(directory)
	runner := &scriptedRunner{t: t, journal: configuration.JournalFile}
	publisher := &fakePublisher{}
	controller, err := New(configuration, 365, runner, publisher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Error(err)
		}
	})
	outcome, err := controller.Run(t.Context(), false)
	if err != nil || outcome != OutcomeActivated {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if len(publisher.records) != 2 {
		t.Fatalf("published %d records, want 2", len(publisher.records))
	}
	if _, err := os.Stat(configuration.JournalFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed journal was not removed: %v", err)
	}
	before := len(runner.calls)
	if outcome, err := controller.Run(t.Context(), false); err != nil || outcome != OutcomeIdle || len(runner.calls) != before {
		t.Fatalf("cadence did not suppress immediate generation: outcome=%q calls=%d err=%v", outcome, len(runner.calls), err)
	}
	if got := commandNames(runner.calls); !reflect.DeepEqual(got, []string{"run", "status", "dns-export", "dns-export", "dns-export", "run"}) {
		t.Fatalf("commands=%v", got)
	}
}

func TestControllerDryRunHasNoDNSOrStateWrites(t *testing.T) {
	directory := protectedTempDir(t)
	configuration := testCampaignConfig(directory)
	publisher := &fakePublisher{}
	runner := RunnerFunc(func(_ context.Context, arguments []string) ([]byte, error) {
		if strings.Join(arguments, " ") != "datasource rotation run --config "+configuration.ConfigFile+" --journal "+configuration.JournalFile+" --automatic --dry-run --machine" {
			t.Fatalf("unexpected dry-run arguments: %v", arguments)
		}
		return reportBytes("run", "planned", 2, 4, 0, "dry_run"), nil
	})
	controller, err := New(configuration, 365, runner, publisher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Error(err)
		}
	})
	if outcome, err := controller.Run(t.Context(), true); err != nil || outcome != OutcomeDryRun {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if len(publisher.records) != 0 {
		t.Fatal("dry-run published DNS")
	}
	if _, err := os.Stat(configuration.JournalFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry-run created journal state")
	}
}

func TestControllerRejectsWritableCampaignDirectory(t *testing.T) {
	directory := protectedTempDir(t)
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	configuration := testCampaignConfig(directory)
	if controller, err := New(configuration, 365, RunnerFunc(func(context.Context, []string) ([]byte, error) {
		return nil, nil
	}), &fakePublisher{}); err == nil || controller != nil {
		t.Fatal("accepted a group-writable campaign artifact directory")
	}
}

func TestProtectedDirectoryRejectsSymlinkArtifact(t *testing.T) {
	directory := protectedTempDir(t)
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "campaign.json")); err != nil {
		t.Fatal(err)
	}
	protected, err := openProtectedDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := protected.close(); err != nil {
			t.Error(err)
		}
	})
	if _, _, err := protected.readRegular("campaign.json", maxArtifactBytes); err == nil {
		t.Fatal("accepted a symlink campaign artifact")
	}
}

func TestProtectedDirectoryReadsOpenedDescriptorAcrossPathExchange(t *testing.T) {
	directory := protectedTempDir(t)
	original := filepath.Join(directory, "campaign.json")
	if err := os.WriteFile(original, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	protected, err := openProtectedDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := protected.close(); err != nil {
			t.Error(err)
		}
	})
	file, _, err := protected.openRegular("campaign.json", maxArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, filepath.Join(directory, "opened-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil || string(document) != "trusted" {
		t.Fatalf("descriptor did not retain the validated object: document=%q err=%v close=%v", document, err, closeErr)
	}
}

func TestParseMachineReportRejectsUnknownAndNonCanonicalDocuments(t *testing.T) {
	valid := reportBytes("status", "staged", 2, 4, 0, "success")
	if _, err := parseMachineReport(valid); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	for _, document := range [][]byte{
		[]byte(strings.TrimSpace(string(valid))),
		[]byte(strings.Replace(string(valid), `"result":"success"`, `"result":"success","domain":"example.test"`, 1)),
		[]byte(strings.Replace(string(valid), `"schema":"dkim2-rotation-report-v1"`, `"schema":"future"`, 1)),
		[]byte(strings.Replace(string(valid), `"state":"staged"`, `"state":"unknown"`, 1)),
	} {
		if _, err := parseMachineReport(document); err == nil {
			t.Fatalf("accepted invalid report %q", document)
		}
	}
}

func testCampaignConfig(directory string) config.DKIM2CampaignConfig {
	return config.DKIM2CampaignConfig{
		Enabled: true, Executable: "/usr/local/bin/dkim2d", ConfigFile: "/run/dkim2/rotation.yaml",
		JournalFile: filepath.Join(directory, "campaign.json"), CadenceFile: filepath.Join(directory, "cadence.json"),
		ArtifactDirectory: directory, MaxBatches: 4,
	}
}

func protectedTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func reportBytes(command, state string, work, records, batches int, result string) []byte {
	return []byte(fmt.Sprintf(`{"schema":"dkim2-rotation-report-v1","command":%q,"mode":"normal","state":%q,"backend":"ldap","work_count":%d,"record_count":%d,"batch_count":%d,"retained_count":0,"unresolved_count":0,"result":%q}`+"\n", command, state, work, records, batches, result))
}

func writeDNSArtifact(t *testing.T, path, owner, public string) {
	t.Helper()
	selector := strings.SplitN(owner, ".", 2)[0]
	document := "; dkim2-dns-export-v1\n; ttl-seconds=300\n; algorithm=ed25519-sha256 selector=" + selector + "\n" + owner + " 300 IN TXT \"v=DKIM1; k=ed25519; p=" + public + "\"\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
}

func argumentValue(arguments []string, name string) string {
	for index := range arguments {
		if arguments[index] == name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func commandNames(calls [][]string) []string {
	result := make([]string, len(calls))
	for index, call := range calls {
		result[index] = call[2]
	}
	return result
}
