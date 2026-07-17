package cli

import "testing"

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

func TestParseTracksExplicitZeroMaxRevoked(t *testing.T) {
	opts, err := Parse([]string{"--list", "--max-revoked", "0"})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.MaxRevokedSet || opts.MaxRevoked != 0 {
		t.Fatalf("explicit zero was not preserved: set=%t value=%d", opts.MaxRevokedSet, opts.MaxRevoked)
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
