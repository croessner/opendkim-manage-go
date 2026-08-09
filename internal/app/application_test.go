package app

import (
	"testing"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

type stubApplication struct{}

func (*stubApplication) Run() (*RunResult, error) { return &RunResult{}, nil }
func (*stubApplication) Close() error             { return nil }

func validFactoryConfig() *config.Config {
	return &config.Config{
		Global: config.GlobalConfig{Mode: types.ModeOpenDKIM},
		LDAP:   config.LDAPConfig{URI: "ldaps://ldap.example.org/ou=dkim,dc=example"},
		DKIM2: config.DKIM2Config{
			TenantID:        "tenant-example",
			ProfileUse:      "originator",
			Rollout:         "enforce",
			Compatibility:   "strict",
			RotateAfterDays: 365, HistoryLimit: 1024, MaxClockSkewSeconds: 300,
			MaxCampaignBindings: 16384, MaxGenerationEntries: 131072,
			MaxAttributeBytes: 64 << 10, MaxDatasetBytes: 1 << 30,
			MaxLDAPRequests: 262144, MaxLDAPBytes: 1 << 30, MaxRetainedRootVisits: 32768,
			IdentifierAllocationAttempts: 32, PublicationReadbackAttempts: 8,
			PublicationReadbackIntervalMillis: 25, LDAPSearchTimeLimitSeconds: 30,
			LDAPOperationTimeoutSeconds: 60, AuthorityPasswordMaxBytes: 16384,
			RunTimeoutSeconds: 900, ProofPollIntervalSeconds: 5, ProofMaxAttempts: 60,
			DNSQueryTimeoutSeconds: 5, RetirementMinOverlapSeconds: 604800,
			Retention: config.DKIM2RetentionConfig{Enabled: true, MaxGenerations: 12,
				MinRollbackGenerations: 2, MaxDeleteBatch: 64, MaxJournalBytes: 4096,
				JournalFile: "/var/lib/opendkim-manage-go/dkim2-retention-plan.json"},
		},
		DNS:     config.DNSConfig{PrimaryNameserver: "127.0.0.1:53", RecursiveNameserver: "127.0.0.2:53"},
		KeyType: types.DKIMKeyTypeRSA,
		Scheme:  types.DefaultScheme(),
	}
}

func TestNewApplicationConstructsOnlySelectedMode(t *testing.T) {
	var openDKIMCalls, dkim2Calls int
	factory := applicationFactory{
		openDKIM: func(*config.Config, *cli.Options) (Application, error) {
			openDKIMCalls++
			return &stubApplication{}, nil
		},
		dkim2: func(*config.Config, *cli.Options) (Application, error) {
			dkim2Calls++
			return &stubApplication{}, nil
		},
	}

	cfg := validFactoryConfig()
	if _, err := factory.newApplication(cfg, &cli.Options{}); err != nil {
		t.Fatalf("construct OpenDKIM: %v", err)
	}
	if openDKIMCalls != 1 || dkim2Calls != 0 {
		t.Fatalf("OpenDKIM dispatch crossed modes: open=%d dkim2=%d", openDKIMCalls, dkim2Calls)
	}

	if _, err := factory.newApplication(cfg, &cli.Options{Mode: types.ModeDKIM2, ModeSet: true}); err != nil {
		t.Fatalf("construct DKIM2: %v", err)
	}
	if openDKIMCalls != 1 || dkim2Calls != 1 {
		t.Fatalf("DKIM2 dispatch crossed modes: open=%d dkim2=%d", openDKIMCalls, dkim2Calls)
	}
}

func TestNewApplicationRejectsInvalidEffectiveModeBeforeConstruction(t *testing.T) {
	constructed := false
	reject := func(*config.Config, *cli.Options) (Application, error) {
		constructed = true
		return &stubApplication{}, nil
	}
	factory := applicationFactory{
		openDKIM: reject,
		dkim2:    reject,
	}

	cfg := validFactoryConfig()
	cfg.Global.Mode = "future"
	if _, err := factory.newApplication(cfg, &cli.Options{}); err == nil {
		t.Fatal("expected invalid effective mode to fail")
	}
	if constructed {
		t.Fatal("application constructor called for invalid mode")
	}
}

func TestNewApplicationValidatesDKIM2OverrideBeforeConstruction(t *testing.T) {
	constructed := false
	factory := applicationFactory{
		dkim2: func(*config.Config, *cli.Options) (Application, error) {
			constructed = true
			return &stubApplication{}, nil
		},
	}
	cfg := validFactoryConfig()
	cfg.DKIM2 = config.DKIM2Config{}
	if _, err := factory.newApplication(cfg, &cli.Options{Mode: types.ModeDKIM2, ModeSet: true}); err == nil {
		t.Fatal("expected missing DKIM2 config to fail")
	}
	if constructed {
		t.Fatal("DKIM2 constructor called before mode-specific validation")
	}
}
