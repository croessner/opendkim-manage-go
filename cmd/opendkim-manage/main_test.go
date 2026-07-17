package main

import (
	"bytes"
	"testing"
)

// TestVersionOutput verifies that the binary reports the build-injected version.
func TestVersionOutput(t *testing.T) {
	previousVersion := version
	version = "test-version"

	t.Cleanup(func() {
		version = previousVersion
	})

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr.String())
	}

	const want = "Version test-version\n"
	if stdout.String() != want {
		t.Fatalf("version output = %q, want %q", stdout.String(), want)
	}
}
