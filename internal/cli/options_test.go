package cli

import (
	"strings"
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/types"
)

func TestParseDryRunAndYes(t *testing.T) {
	opts, err := Parse([]string{"--create", "--domain", "example.org", "--dry-run", "--yes"})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.DryRun {
		t.Fatal("expected dry-run to be enabled")
	}
	if !opts.Yes {
		t.Fatal("expected yes to be enabled")
	}
}

func TestParseAcceptsNativeDKIM2RotationForms(t *testing.T) {
	opts, err := Parse([]string{
		"--mode", "dkim2", "--rotate", "--domain", "example.test", "--update-dns",
		"--prepare-only", "--resume-generation", "42",
	})
	if err != nil {
		t.Fatalf("parse DKIM2 rotation: %v", err)
	}
	if !opts.Rotate || !opts.PrepareOnly || !opts.ResumeGenerationSet || opts.ResumeGeneration != 42 {
		t.Fatalf("rotation controls were not retained: %#v", opts)
	}
}

func TestParseRejectsNoncanonicalGenerationArguments(t *testing.T) {
	for _, flag := range []string{"--resume-generation", "--retire-generation", "--rollback-from-generation"} {
		for _, value := range []string{"", "0", "00", "+1", " 1", "1 "} {
			_, err := Parse([]string{"--list", flag + "=" + value})
			if err == nil {
				t.Fatalf("%s accepted %q", flag, value)
			}
		}
	}
}

func TestValidateForModePreservesOpenDKIMRotateScope(t *testing.T) {
	opts, err := Parse([]string{"--rotate", "--domain", "example.test"})
	if err != nil {
		t.Fatalf("generic parse unexpectedly rejected deferred scope: %v", err)
	}
	if err := opts.ValidateForMode(types.ModeOpenDKIM); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("OpenDKIM rotation scope error = %v", err)
	}
	if err := opts.ValidateForMode(types.ModeDKIM2); err != nil {
		t.Fatalf("DKIM2 rotation scope rejected: %v", err)
	}
}

func TestParseRetirementAttestationsAreBooleanAndScoped(t *testing.T) {
	flags := []string{
		"--attest-runtime-reload", "--attest-readiness", "--attest-queues",
		"--attest-emitted-signatures", "--attest-external-verification",
		"--attest-backup", "--attest-rollback-authority",
	}
	args := append([]string{"--retire-generation", "7", "--domain", "example.test", "--update-dns"}, flags...)
	opts, err := Parse(args)
	if err != nil {
		t.Fatalf("parse retirement: %v", err)
	}
	if opts.RetireGeneration != 7 || !opts.AllRetirementAttestations() {
		t.Fatalf("retirement controls incomplete: %#v", opts)
	}
	if _, err := Parse([]string{"--list", "--attest-backup"}); err == nil {
		t.Fatal("attestation outside retirement was accepted")
	}
	for _, flag := range flags {
		for _, value := range []string{"true", "false"} {
			if _, err := Parse([]string{"--retire-generation", "7", "--domain", "example.test", "--update-dns", flag + "=" + value}); err == nil {
				t.Fatalf("presence-only attestation accepted value syntax %s=%s", flag, value)
			}
		}
	}
}

func TestParseRejectsEveryPositionalArgumentAfterFlagParsing(t *testing.T) {
	for _, args := range [][]string{
		{"unexpected"},
		{"--list", "unexpected"},
		{"--retire-generation", "7", "--domain", "example.test", "--update-dns", "--attest-runtime-reload", "false"},
	} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("positional argument accepted: %q", args)
		}
	}
}

func TestParseTracksExplicitZeroMaxRevoked(t *testing.T) {
	opts, err := Parse([]string{"--list", "--max-revoked", "0"})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.MaxRevokedSet || opts.MaxRevoked != 0 {
		t.Fatalf("explicit zero was not preserved: set=%t value=%d", opts.MaxRevokedSet, opts.MaxRevoked)
	}
}

func TestParseObserveIsDKIM2OnlyAndPrimary(t *testing.T) {
	opts, err := Parse([]string{"--mode", "dkim2", "--observe", "--domain", "example.test"})
	if err != nil || !opts.Observe {
		t.Fatalf("observe parse options=%#v err=%v", opts, err)
	}
	if err := opts.ValidateForMode(types.ModeDKIM2); err != nil {
		t.Fatalf("DKIM2 observe rejected: %v", err)
	}
	if err := opts.ValidateForMode(types.ModeOpenDKIM); err == nil {
		t.Fatal("OpenDKIM observe accepted")
	}
	if _, err := Parse([]string{"--observe", "--list", "--domain", "example.test"}); err == nil {
		t.Fatal("observe combined with another primary command")
	}
}

func TestParseRejectsAgeTogetherWithAnotherCommand(t *testing.T) {
	if _, err := Parse([]string{"--list", "--age", "1", "--selectorname", "s1"}); err == nil {
		t.Fatal("expected mutually exclusive command error")
	}
}

func TestParseRejectsAgeWithoutValue(t *testing.T) {
	if _, err := Parse([]string{"--age", "--selectorname", "s1"}); err == nil {
		t.Fatal("expected --age without a value to fail")
	}
}

func TestParseRejectsTestKeyWithoutScope(t *testing.T) {
	if _, err := Parse([]string{"--testkey"}); err == nil {
		t.Fatal("expected --testkey without domain or selector to fail")
	}
}

func TestParseModeOverrideIsExactAndOptional(t *testing.T) {
	opts, err := Parse([]string{"--list"})
	if err != nil {
		t.Fatalf("parse default: %v", err)
	}
	if opts.ModeSet {
		t.Fatal("mode unexpectedly marked as explicitly set")
	}
	if got := opts.EffectiveMode(types.ModeOpenDKIM); got != types.ModeOpenDKIM {
		t.Fatalf("effective default mode = %q", got)
	}

	opts, err = Parse([]string{"--list", "--mode", "dkim2"})
	if err != nil {
		t.Fatalf("parse DKIM2 override: %v", err)
	}
	if !opts.ModeSet || opts.Mode != types.ModeDKIM2 {
		t.Fatalf("mode override not retained: set=%t mode=%q", opts.ModeSet, opts.Mode)
	}

	for _, value := range []string{"", "DKIM2", " dkim2", "future"} {
		if _, err := Parse([]string{"--list", "--mode=" + value}); err == nil {
			t.Fatalf("expected exact mode value %q to fail", value)
		}
	}
}
