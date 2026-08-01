// Package dkim2store persists complete immutable DKIM2 datasource generations.
package dkim2store

import (
	"context"
	"errors"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

var (
	// ErrUnavailable identifies an uncertain LDAP result without retaining backend details.
	ErrUnavailable = errors.New("DKIM2 LDAP repository unavailable")
	// ErrMalformed identifies an incomplete or ambiguous DKIM2 LDAP dataset.
	ErrMalformed = errors.New("DKIM2 LDAP dataset is malformed")
	// ErrConflict identifies a stale generation fence or concurrent publisher.
	ErrConflict = errors.New("DKIM2 LDAP generation conflict")
)

// GenerationRepository owns complete generation loads and atomic publication.
type GenerationRepository interface {
	LoadCurrent(context.Context) (*dkim2model.Generation, error)
	Publish(context.Context, uint64, *dkim2model.Generation) error
}
