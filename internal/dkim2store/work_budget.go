package dkim2store

import (
	"context"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

type ldapWorkBudgetKey struct{}

type ldapWorkBudget struct {
	mu               sync.Mutex
	requests         int
	bytes            int
	historyRoots     int
	maximumRequests  int
	maximumBytes     int
	maximumHistories int
}

// WithLifecycleWorkBudget binds cumulative LDAP work to one configured lifecycle run.
func WithLifecycleWorkBudget(ctx context.Context, historyLimit int) context.Context {
	if ctx == nil || historyLimit < 2 || historyLimit > 4096 {
		return ctx
	}
	maximumHistoryBytes := maximumDatasetBytes * min(historyLimit, 8)
	budget := &ldapWorkBudget{
		maximumRequests:  128 + 64*historyLimit,
		maximumBytes:     maximumHistoryBytes,
		maximumHistories: 16 * historyLimit,
	}
	return context.WithValue(ctx, ldapWorkBudgetKey{}, budget)
}

func workBudgetFromContext(ctx context.Context) *ldapWorkBudget {
	if ctx == nil {
		return nil
	}
	budget, _ := ctx.Value(ldapWorkBudgetKey{}).(*ldapWorkBudget)
	return budget
}

func (b *ldapWorkBudget) consume(requests, bytes, histories int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if requests < 0 || bytes < 0 || histories < 0 ||
		b.requests > b.maximumRequests-requests ||
		b.bytes > b.maximumBytes-bytes ||
		b.historyRoots > b.maximumHistories-histories {
		return ErrUnavailable
	}
	b.requests += requests
	b.bytes += bytes
	b.historyRoots += histories
	return nil
}

func ldapSearchResultBytes(result *ldap.SearchResult) (int, error) {
	if result == nil {
		return 0, nil
	}
	total := 0
	for _, entry := range result.Entries {
		if entry == nil || total > maximumDatasetBytes-len(entry.DN) {
			return 0, ErrUnavailable
		}
		total += len(entry.DN)
		for _, attribute := range entry.Attributes {
			if attribute == nil || total > maximumDatasetBytes-len(attribute.Name) {
				return 0, ErrUnavailable
			}
			total += len(attribute.Name)
			for _, value := range attribute.ByteValues {
				if total > maximumDatasetBytes-len(value) {
					return 0, ErrUnavailable
				}
				total += len(value)
			}
		}
	}
	return total, nil
}

func ldapAddRequestBytes(request *ldap.AddRequest) int {
	if request == nil {
		return 0
	}
	total := len(request.DN)
	for _, attribute := range request.Attributes {
		total += len(attribute.Type)
		for _, value := range attribute.Vals {
			total += len(value)
		}
	}
	return total
}

func ldapModifyRequestBytes(request *ldap.ModifyRequest) int {
	if request == nil {
		return 0
	}
	total := len(request.DN)
	for _, change := range request.Changes {
		total += len(change.Modification.Type)
		for _, value := range change.Modification.Vals {
			total += len(value)
		}
	}
	return total
}
