package app

import (
	"errors"
	"fmt"

	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/types"
)

// Application is the command boundary shared by structurally isolated modes.
type Application interface {
	Run() (*RunResult, error)
	Close() error
}

type applicationConstructor func(*config.Config, *cli.Options) (Application, error)

type applicationFactory struct {
	openDKIM applicationConstructor
	dkim2    applicationConstructor
}

// NewApplication validates and constructs only the selected mode implementation.
func NewApplication(cfg *config.Config, opts *cli.Options) (Application, error) {
	factory := applicationFactory{
		openDKIM: func(cfg *config.Config, opts *cli.Options) (Application, error) {
			return NewManager(cfg, opts)
		},
		dkim2: func(cfg *config.Config, opts *cli.Options) (Application, error) {
			return NewDKIM2Manager(cfg, opts)
		},
	}
	return factory.newApplication(cfg, opts)
}

// newApplication dispatches through injected constructors without probing the unselected mode.
func (f applicationFactory) newApplication(cfg *config.Config, opts *cli.Options) (Application, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if opts == nil {
		return nil, errors.New("command options are required")
	}

	mode := opts.EffectiveMode(cfg.Global.Mode)
	if err := cfg.ValidateForMode(mode); err != nil {
		return nil, err
	}

	switch mode {
	case types.ModeOpenDKIM:
		if f.openDKIM == nil {
			return nil, errors.New("opendkim application constructor is unavailable")
		}
		return f.openDKIM(cfg, opts)
	case types.ModeDKIM2:
		if f.dkim2 == nil {
			return nil, errors.New("dkim2 application constructor is unavailable")
		}
		return f.dkim2(cfg, opts)
	default:
		return nil, fmt.Errorf("unsupported application mode %q", mode)
	}
}
