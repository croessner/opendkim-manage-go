package app

import (
	"time"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
)

// configuredDKIM2StoreLimits transfers every validated repository bound without deriving hidden limits.
func configuredDKIM2StoreLimits(cfg config.DKIM2Config) dkim2store.Limits {
	return dkim2store.Limits{
		HistoryLimit: cfg.HistoryLimit, MaxGenerationEntries: cfg.MaxGenerationEntries,
		MaxAttributeBytes: cfg.MaxAttributeBytes, MaxDatasetBytes: cfg.MaxDatasetBytes,
		MaxLDAPRequests: cfg.MaxLDAPRequests, MaxLDAPBytes: cfg.MaxLDAPBytes,
		MaxRetainedRootVisits:       cfg.MaxRetainedRootVisits,
		PublicationReadbackAttempts: cfg.PublicationReadbackAttempts,
		PublicationReadbackInterval: time.Duration(cfg.PublicationReadbackIntervalMillis) * time.Millisecond,
		SearchTimeLimitSeconds:      cfg.LDAPSearchTimeLimitSeconds,
	}
}

// configuredDKIM2RotationLimits transfers every validated global-planning bound.
func configuredDKIM2RotationLimits(cfg config.DKIM2Config, rsaBits int) dkim2model.RotationLimits {
	return dkim2model.RotationLimits{
		RotateAfter:        time.Duration(cfg.RotateAfterDays) * 24 * time.Hour,
		MaximumClockSkew:   time.Duration(cfg.MaxClockSkewSeconds) * time.Second,
		AllocationAttempts: cfg.IdentifierAllocationAttempts,
		RSABits:            rsaBits, MaximumBindings: cfg.MaxCampaignBindings,
	}
}
