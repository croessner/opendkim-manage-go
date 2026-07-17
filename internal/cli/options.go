package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/croessner/opendkim-manage-go/internal/types"
)

type Options struct {
	List            bool
	Create          bool
	Delete          bool
	ForceDelete     bool
	Active          bool
	ForceActive     bool
	Age             *int
	Domains         []string
	Selectors       []string
	Size            int
	KeyType         string
	TestKey         bool
	ConfigPath      string
	AddMissing      bool
	MaxInitial      int
	MaxRevoked      int
	MaxRevokedSet   bool
	AddNew          bool
	Rotate          bool
	Auto            bool
	PrintDNS        bool
	AcceptAnyDomain bool
	ExpireAfter     *int
	DeleteDelay     *int
	UpdateDNS       bool
	DryRun          bool
	Yes             bool
	Interactive     bool
	Debug           bool
	Verbose         bool
	Color           bool
	ShowVersion     bool
}

func Parse(args []string) (*Options, error) {
	o := &Options{}
	fs := pflag.NewFlagSet("opendkim-manage", pflag.ContinueOnError)

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

	if err := fs.Parse(args); err != nil {
		return nil, err
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

	if err := o.Validate(); err != nil {
		return nil, err
	}
	return o, nil
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

	if (o.AddMissing || o.AddNew || o.Rotate || o.Auto) && (len(o.Domains) > 0 || len(o.Selectors) > 0) {
		return errors.New("--domain/--selectorname are not allowed with --add-missing,--add-new,--rotate,--auto")
	}

	if o.TestKey && len(o.Domains) > 0 && len(o.Selectors) > 0 {
		return errors.New("use only one of --domain or --selectorname with --testkey")
	}

	if o.Delete && len(o.Domains) == 0 && len(o.Selectors) == 0 {
		return errors.New("--delete requires --domain and/or --selectorname")
	}

	commands := 0
	for _, enabled := range []bool{o.List, o.Create, o.Delete, o.Age != nil, o.Active, o.TestKey, o.Rotate, o.AddMissing, o.AddNew, o.PrintDNS, o.Auto} {
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

	return nil
}

func (o *Options) EffectiveKeyType(defaultType types.DKIMKeyType) types.DKIMKeyType {
	if o.KeyType == "" {
		return defaultType
	}
	kt, _ := types.ParseDKIMKeyType(o.KeyType)
	return kt
}
