package selector

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("random source failed")
}

func TestBuilderParse(t *testing.T) {
	b := Builder{
		Format: "s${randomhex:8}-${year}${month}${day}",
		Now: func() time.Time {
			return time.Date(2026, 3, 14, 8, 0, 0, 0, time.UTC)
		},
	}
	name, err := b.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(name, "s") {
		t.Fatalf("unexpected selector prefix: %s", name)
	}
	if !strings.Contains(name, "20260314") {
		t.Fatalf("expected static date replacement, got %s", name)
	}
}

func TestBuilderReportsRandomSourceFailure(t *testing.T) {
	b := Builder{Format: "s${randomhex:8}", Random: failingReader{}}
	if _, err := b.Parse(); err == nil {
		t.Fatal("expected random source failure")
	}
}

func TestValidateRecordName(t *testing.T) {
	if err := ValidateRecordName("selector1", "example.com"); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if err := ValidateRecordName(strings.Repeat("a", 64), "example.com"); err == nil {
		t.Fatalf("expected validation error for long label")
	}
}
