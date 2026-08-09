package app

import (
	"testing"
	"time"

	"github.com/croessner/opendkim-manage-go/internal/config"
)

func TestConfiguredDKIM2LimitsPreserveEveryEffectiveValue(t *testing.T) {
	cfg := config.DKIM2Config{
		RotateAfterDays: 31, HistoryLimit: 257, MaxCampaignBindings: 129,
		MaxGenerationEntries: 8193, MaxAttributeBytes: 32769, MaxDatasetBytes: 16777217,
		MaxLDAPRequests: 4097, MaxLDAPBytes: 33554433, MaxRetainedRootVisits: 513,
		IdentifierAllocationAttempts: 25, PublicationReadbackAttempts: 7, PublicationReadbackIntervalMillis: 41,
		LDAPSearchTimeLimitSeconds: 13, MaxClockSkewSeconds: 121,
	}
	store := configuredDKIM2StoreLimits(cfg)
	if store.HistoryLimit != 257 || store.MaxGenerationEntries != 8193 || store.MaxAttributeBytes != 32769 ||
		store.MaxDatasetBytes != 16777217 || store.MaxLDAPRequests != 4097 || store.MaxLDAPBytes != 33554433 ||
		store.MaxRetainedRootVisits != 513 || store.PublicationReadbackAttempts != 7 ||
		store.PublicationReadbackInterval != 41*time.Millisecond ||
		store.SearchTimeLimitSeconds != 13 {
		t.Fatalf("store limits lost a configured value: %#v", store)
	}
	rotation := configuredDKIM2RotationLimits(cfg, 3072)
	if rotation.RotateAfter != 31*24*time.Hour || rotation.MaximumClockSkew != 121*time.Second ||
		rotation.AllocationAttempts != 25 || rotation.RSABits != 3072 || rotation.MaximumBindings != 129 {
		t.Fatalf("rotation limits lost a configured value: %#v", rotation)
	}
}
