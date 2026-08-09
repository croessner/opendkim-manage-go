package dkim2store

import "time"

// Limits contains every externally configured LDAP repository work bound.
type Limits struct {
	HistoryLimit                int
	MaxGenerationEntries        int
	MaxAttributeBytes           int
	MaxDatasetBytes             int
	MaxLDAPRequests             int
	MaxLDAPBytes                int
	MaxRetainedRootVisits       int
	PublicationReadbackAttempts int
	PublicationReadbackInterval time.Duration
	SearchTimeLimitSeconds      int
}

// Validate rejects absent operational bounds instead of deriving hidden defaults.
func (l Limits) Validate() error {
	if l.HistoryLimit < 2 || l.MaxGenerationEntries < 6 || l.MaxAttributeBytes <= 0 ||
		l.MaxDatasetBytes < l.MaxAttributeBytes || l.MaxLDAPRequests <= 0 ||
		l.MaxLDAPBytes < l.MaxDatasetBytes || l.MaxRetainedRootVisits < l.HistoryLimit ||
		l.PublicationReadbackAttempts <= 0 || l.PublicationReadbackInterval <= 0 ||
		l.SearchTimeLimitSeconds <= 0 {
		return ErrMalformed
	}
	return nil
}
