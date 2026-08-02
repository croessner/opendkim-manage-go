package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/croessner/opendkim-manage-go/internal/types"
)

type Options struct {
	Mode                       types.Mode
	ModeSet                    bool
	List                       bool
	Create                     bool
	Delete                     bool
	ForceDelete                bool
	Active                     bool
	ForceActive                bool
	Age                        *int
	Domains                    []string
	Selectors                  []string
	Size                       int
	KeyType                    string
	TestKey                    bool
	ConfigPath                 string
	AddMissing                 bool
	MaxInitial                 int
	MaxRevoked                 int
	MaxRevokedSet              bool
	AddNew                     bool
	Rotate                     bool
	Auto                       bool
	PrintDNS                   bool
	Observe                    bool
	AcceptAnyDomain            bool
	ExpireAfter                *int
	DeleteDelay                *int
	UpdateDNS                  bool
	DryRun                     bool
	Yes                        bool
	Interactive                bool
	Debug                      bool
	Verbose                    bool
	Color                      bool
	ShowVersion                bool
	PrepareOnly                bool
	ResumeGeneration           uint64
	ResumeGenerationSet        bool
	RetireGeneration           uint64
	RetireGenerationSet        bool
	RollbackFromGeneration     uint64
	RollbackFromGenerationSet  bool
	ResumeRetirement           bool
	AttestRuntimeReload        bool
	AttestReadiness            bool
	AttestQueues               bool
	AttestEmittedSignatures    bool
	AttestExternalVerification bool
	AttestBackup               bool
	AttestRollbackAuthority    bool
}

func Parse(args []string) (*Options, error) {
	o := &Options{}
	fs := pflag.NewFlagSet("opendkim-manage", pflag.ContinueOnError)
	var mode string
	var resumeGeneration, retireGeneration, rollbackFromGeneration string
	for _, argument := range args {
		if strings.HasPrefix(argument, "--attest-") && strings.Contains(argument, "=") {
			return nil, errors.New("retirement attestations are boolean flags and do not accept values")
		}
	}

	fs.StringVar(&mode, "mode", "", "Application mode: opendkim or dkim2")
	fs.BoolVarP(&o.List, "list", "l", false, "List DKIM keys")
	fs.BoolVarP(&o.Create, "create", "c", false, "Create a new DKIM key")
	fs.BoolVarP(&o.Delete, "delete", "d", false, "Delete one or many DKIM keys")
	fs.BoolVar(&o.ForceDelete, "force-delete", false, "Force deletion of a DKIM key")
	fs.BoolVar(&o.Active, "active", false, "Set DKIMActive to TRUE for a selector")
	fs.BoolVar(&o.ForceActive, "force-active", false, "Force activation of a DKIM key")

	var age int
	fs.IntVarP(&age, "age", "A", 0, "The key has to be more(+) or less(-) than n days old")

	fs.StringSliceVarP(&o.Domains, "domain", "D", nil, "A DNS domain name")
	fs.StringSliceVarP(&o.Selectors, "selectorname", "s", nil, "A selector name")
	fs.IntVarP(&o.Size, "size", "S", 2048, "Size of DKIM RSA keys")
	fs.StringVarP(&o.KeyType, "keytype", "k", "", "Key type: both,rsa,ed25519")
	fs.BoolVarP(&o.TestKey, "testkey", "t", false, "Check that listed DKIM keys are published and useable")
	fs.StringVarP(&o.ConfigPath, "config", "f", "/etc/opendkim-manage.yaml", "Path to config file")
	fs.BoolVarP(&o.AddMissing, "add-missing", "m", false, "Add missing DKIM keys")
	fs.IntVar(&o.MaxInitial, "max-initial", 0, "Maximum number of newly created DKIM keys")
	fs.IntVarP(&o.MaxRevoked, "max-revoked", "R", 6, "Maximum number of revoked DKIM keys kept")
	fs.BoolVarP(&o.AddNew, "add-new", "n", false, "Create new keys on demand")
	fs.BoolVarP(&o.Rotate, "rotate", "r", false, "Rotate one or all DKIM keys")
	fs.BoolVarP(&o.Auto, "auto", "a", false, "Shortcut for add-missing,add-new,rotate,delete")
	fs.BoolVar(&o.PrintDNS, "print-dns", false, "Print public DNS information")
	fs.BoolVar(&o.Observe, "observe", false, "Observe bounded DKIM2 lifecycle state")
	fs.BoolVar(&o.AcceptAnyDomain, "accept-any-domain", false, "Do not fail for unknown domains in print-dns")

	var exp int
	fs.IntVarP(&exp, "expire-after", "e", 0, "Days until new key creation")
	var del int
	fs.IntVarP(&del, "delete-delay", "y", 0, "Delay before deletion of old keys")

	fs.BoolVarP(&o.UpdateDNS, "update-dns", "u", false, "Update DNS zones")
	fs.BoolVar(&o.DryRun, "dry-run", false, "Plan LDAP and DNS changes without writing them")
	fs.BoolVar(&o.Yes, "yes", false, "Confirm non-interactive LDAP and DNS changes")
	fs.BoolVarP(&o.Interactive, "interactive", "i", false, "Interactive mode")
	fs.BoolVar(&o.Debug, "debug", false, "Enable debug output")
	fs.BoolVarP(&o.Verbose, "verbose", "v", false, "Verbose output")
	fs.BoolVar(&o.Color, "color", false, "Color output")
	fs.BoolVarP(&o.ShowVersion, "version", "V", false, "Print version and exit")
	fs.BoolVar(&o.PrepareOnly, "prepare-only", false, "Stage a DKIM2 candidate without DNS activity")
	fs.StringVar(&resumeGeneration, "resume-generation", "", "Resume one exact staged DKIM2 generation")
	fs.StringVar(&retireGeneration, "retire-generation", "", "Retire DNS records for one exact retained generation")
	fs.StringVar(&rollbackFromGeneration, "rollback-from-generation", "", "Rebase one exact retained generation forward")
	fs.BoolVar(&o.ResumeRetirement, "resume-retirement", false, "Resume an explicitly authorized DKIM2 retirement")
	fs.BoolVar(&o.AttestRuntimeReload, "attest-runtime-reload", false, "Attest runtime reload verification")
	fs.BoolVar(&o.AttestReadiness, "attest-readiness", false, "Attest repeated readiness verification")
	fs.BoolVar(&o.AttestQueues, "attest-queues", false, "Attest queue verification")
	fs.BoolVar(&o.AttestEmittedSignatures, "attest-emitted-signatures", false, "Attest emitted-signature verification")
	fs.BoolVar(&o.AttestExternalVerification, "attest-external-verification", false, "Attest external verification")
	fs.BoolVar(&o.AttestBackup, "attest-backup", false, "Attest protected backup readiness")
	fs.BoolVar(&o.AttestRollbackAuthority, "attest-rollback-authority", false, "Attest rollback authority")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, errors.New("positional arguments are not accepted")
	}

	if fs.Lookup("age").Changed {
		o.Age = &age
	}
	if fs.Lookup("expire-after").Changed {
		o.ExpireAfter = &exp
	}
	if fs.Lookup("delete-delay").Changed {
		o.DeleteDelay = &del
	}
	o.MaxRevokedSet = fs.Lookup("max-revoked").Changed
	o.ModeSet = fs.Lookup("mode").Changed
	if o.ModeSet {
		parsedMode, err := types.ParseMode(mode)
		if err != nil {
			return nil, fmt.Errorf("invalid --mode: %w", err)
		}
		o.Mode = parsedMode
	}
	var err error
	if o.ResumeGenerationSet = fs.Lookup("resume-generation").Changed; o.ResumeGenerationSet {
		o.ResumeGeneration, err = parseGenerationArgument(resumeGeneration)
		if err != nil {
			return nil, fmt.Errorf("invalid --resume-generation: %w", err)
		}
	}
	if o.RetireGenerationSet = fs.Lookup("retire-generation").Changed; o.RetireGenerationSet {
		o.RetireGeneration, err = parseGenerationArgument(retireGeneration)
		if err != nil {
			return nil, fmt.Errorf("invalid --retire-generation: %w", err)
		}
	}
	if o.RollbackFromGenerationSet = fs.Lookup("rollback-from-generation").Changed; o.RollbackFromGenerationSet {
		o.RollbackFromGeneration, err = parseGenerationArgument(rollbackFromGeneration)
		if err != nil {
			return nil, fmt.Errorf("invalid --rollback-from-generation: %w", err)
		}
	}

	if err := o.Validate(); err != nil {
		return nil, err
	}
	return o, nil
}

// EffectiveMode applies an exact command-line override to the configured mode.
func (o *Options) EffectiveMode(configured types.Mode) types.Mode {
	if o != nil && o.ModeSet {
		return o.Mode
	}
	return configured
}

func (o *Options) Validate() error {
	if o.Create && len(o.Domains) == 0 {
		return errors.New("--create requires --domain")
	}

	if (o.Age != nil || o.Active) && len(o.Selectors) == 0 {
		return errors.New("--age/--active require --selectorname")
	}
	if (o.Age != nil || o.Active) && len(o.Selectors) != 1 {
		return errors.New("--age/--active require exactly one --selectorname")
	}
	if (o.Age != nil || o.Active) && len(o.Domains) > 1 {
		return errors.New("--age/--active accept at most one --domain")
	}
	if o.TestKey && len(o.Domains) == 0 && len(o.Selectors) == 0 {
		return errors.New("--testkey requires --domain or --selectorname")
	}

	if (o.AddMissing || o.AddNew || o.Auto) && (len(o.Domains) > 0 || len(o.Selectors) > 0) {
		return errors.New("--domain/--selectorname are not allowed with --add-missing,--add-new,--auto")
	}

	if o.TestKey && len(o.Domains) > 0 && len(o.Selectors) > 0 {
		return errors.New("use only one of --domain or --selectorname with --testkey")
	}

	if o.Delete && len(o.Domains) == 0 && len(o.Selectors) == 0 {
		return errors.New("--delete requires --domain and/or --selectorname")
	}

	commands := 0
	for _, enabled := range []bool{o.List, o.Create, o.Delete, o.Age != nil, o.Active, o.TestKey, o.Rotate, o.AddMissing, o.AddNew, o.PrintDNS, o.Observe, o.Auto, o.RetireGenerationSet, o.RollbackFromGenerationSet} {
		if enabled {
			commands++
		}
	}
	if commands > 1 {
		return errors.New("only one primary command at a time is allowed")
	}

	if o.Size <= 1024 {
		return errors.New("--size must be greater than 1024")
	}

	if o.KeyType != "" {
		s := strings.ToLower(strings.TrimSpace(o.KeyType))
		if _, err := types.ParseDKIMKeyType(s); err != nil || s == "revoked" {
			return fmt.Errorf("invalid --keytype: %s", o.KeyType)
		}
		o.KeyType = s
	}

	if o.MaxInitial < 0 {
		return errors.New("--max-initial must be >= 0")
	}
	if o.MaxRevoked < 0 {
		return errors.New("--max-revoked must be >= 0")
	}
	if o.ExpireAfter != nil && (*o.ExpireAfter <= 0 || *o.ExpireAfter > 36500) {
		return errors.New("--expire-after must be between 1 and 36500 days")
	}
	if o.DeleteDelay != nil && (*o.DeleteDelay < 0 || *o.DeleteDelay > 36500) {
		return errors.New("--delete-delay must be between 0 and 36500 days")
	}
	if o.ForceDelete && !o.Delete {
		return errors.New("--force-delete requires --delete")
	}
	if o.ForceActive && !o.Active && !o.Rotate && !o.Auto {
		return errors.New("--force-active requires --active, --rotate, or --auto")
	}
	if o.PrepareOnly && !o.Rotate && !o.RollbackFromGenerationSet {
		return errors.New("--prepare-only requires --rotate or --rollback-from-generation")
	}
	if o.ResumeGenerationSet && !o.Rotate && !o.RollbackFromGenerationSet {
		return errors.New("--resume-generation requires --rotate or --rollback-from-generation")
	}
	if o.ResumeRetirement && !o.RetireGenerationSet {
		return errors.New("--resume-retirement requires --retire-generation")
	}
	if o.anyRetirementAttestation() && !o.RetireGenerationSet {
		return errors.New("retirement attestations require --retire-generation")
	}

	return nil
}

// ValidateForMode applies command semantics that depend on the effective mode.
func (o *Options) ValidateForMode(mode types.Mode) error {
	if o == nil {
		return errors.New("command options are required")
	}
	if mode == types.ModeOpenDKIM {
		if o.RetireGenerationSet || o.RollbackFromGenerationSet || o.ResumeGenerationSet ||
			o.ResumeRetirement || o.PrepareOnly || o.Observe || o.anyRetirementAttestation() {
			return errors.New("DKIM2 lifecycle controls are invalid in opendkim mode")
		}
		if o.Rotate && (len(o.Domains) > 0 || len(o.Selectors) > 0) {
			return errors.New("--domain/--selectorname are not allowed with --rotate in opendkim mode")
		}
	}
	return nil
}

// AllRetirementAttestations reports whether every required operator assertion is present.
func (o *Options) AllRetirementAttestations() bool {
	return o != nil && o.AttestRuntimeReload && o.AttestReadiness && o.AttestQueues &&
		o.AttestEmittedSignatures && o.AttestExternalVerification && o.AttestBackup &&
		o.AttestRollbackAuthority
}

func (o *Options) anyRetirementAttestation() bool {
	return o != nil && (o.AttestRuntimeReload || o.AttestReadiness || o.AttestQueues ||
		o.AttestEmittedSignatures || o.AttestExternalVerification || o.AttestBackup ||
		o.AttestRollbackAuthority)
}

func parseGenerationArgument(value string) (uint64, error) {
	if value == "" || len(value) > 20 || value[0] == '0' {
		return 0, errors.New("generation must be a canonical nonzero decimal")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("generation must be a canonical nonzero decimal")
		}
	}
	generation, err := strconv.ParseUint(value, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != value {
		return 0, errors.New("generation must be a canonical nonzero decimal")
	}
	return generation, nil
}

func (o *Options) EffectiveKeyType(defaultType types.DKIMKeyType) types.DKIMKeyType {
	if o.KeyType == "" {
		return defaultType
	}
	kt, _ := types.ParseDKIMKeyType(o.KeyType)
	return kt
}
