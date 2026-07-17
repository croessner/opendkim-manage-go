package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"

	"github.com/croessner/opendkim-manage-go/internal/app"
	"github.com/croessner/opendkim-manage-go/internal/cli"
	"github.com/croessner/opendkim-manage-go/internal/config"
)

var version = "dev"

// main delegates to run so command behavior stays testable at the binary boundary.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses command-line options and returns the intended process exit code.
func run(args []string, stdout io.Writer, stderr io.Writer) int {
	opts, err := cli.Parse(args)
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}

		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)

		return 64
	}

	if opts.ShowVersion {
		_, _ = fmt.Fprintf(stdout, "Version %s\n", version)

		return 0
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)

		return 70
	}

	manager, err := app.NewManager(cfg, opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)

		return 70
	}
	defer func() {
		if err := manager.Close(); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error closing LDAP connections: %v\n", err)
		}
	}()

	result, err := manager.Run()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)

		return 70
	}

	if result != nil && result.AgeMatched != nil {
		if *result.AgeMatched {
			return 0
		}

		return 1
	}

	return 0
}
