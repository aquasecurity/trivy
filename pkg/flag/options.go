package flag

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
)

type Flag struct {
	// Name is for CLI flag and environment variable.
	// If this field is empty, it will be available only in config file.
	Name string

	// ConfigName is a key in config file. It is also used as a key of viper.
	ConfigName string

	// Shorthand is a shorthand letter.
	Shorthand string

	// Value is the default value. It must be filled to determine the flag type.
	Value interface{}

	// Usage explains how to use the flag.
	Usage string

	// Persistent represents if the flag is persistent
	Persistent bool

	// Deprecated represents if the flag is deprecated
	Deprecated bool

	// Aliases represents aliases
	Aliases []Alias
}

type Alias struct {
	Name       string
	ConfigName string
	Deprecated bool
}

type FlagGroup interface {
	Name() string
	Flags() []*Flag
}

type Flags struct {
	AWSFlagGroup           *AWSFlagGroup
	CacheFlagGroup         *CacheFlagGroup
	CloudFlagGroup         *CloudFlagGroup
	DBFlagGroup            *DBFlagGroup
	ImageFlagGroup         *ImageFlagGroup
	K8sFlagGroup           *K8sFlagGroup
	LicenseFlagGroup       *LicenseFlagGroup
	MisconfFlagGroup       *MisconfFlagGroup
	ModuleFlagGroup        *ModuleFlagGroup
	RemoteFlagGroup        *RemoteFlagGroup
	RegistryFlagGroup      *RegistryFlagGroup
	RegoFlagGroup          *RegoFlagGroup
	RepoFlagGroup          *RepoFlagGroup
	ReportFlagGroup        *ReportFlagGroup
	SBOMFlagGroup          *SBOMFlagGroup
	ScanFlagGroup          *ScanFlagGroup
	SecretFlagGroup        *SecretFlagGroup
	VulnerabilityFlagGroup *VulnerabilityFlagGroup
}

// Options holds all the runtime configuration
type Options struct {
	GlobalOptions
	AWSOptions
	CacheOptions
	CloudOptions
	DBOptions
	ImageOptions
	K8sOptions
	LicenseOptions
	MisconfOptions
	ModuleOptions
	RegistryOptions
	RegoOptions
	RemoteOptions
	RepoOptions
	ReportOptions
	SBOMOptions
	ScanOptions
	SecretOptions
	VulnerabilityOptions

	// Trivy's version, not populated via CLI flags
	AppVersion string

	// We don't want to allow disabled analyzers to be passed by users, but it is necessary for internal use.
	DisabledAnalyzers []analyzer.Type
}

// Align takes consistency of options
func (o *Options) Align() {
	if o.Format == report.FormatSPDX || o.Format == report.FormatSPDXJSON {
		log.Logger.Info(`"--format spdx" and "--format spdx-json" disable security scanning`)
		o.Scanners = nil
	}

	// Vulnerability scanning is disabled by default for CycloneDX.
	if o.Format == report.FormatCycloneDX && !viper.IsSet(ScannersFlag.ConfigName) {
		log.Logger.Info(`"--format cyclonedx" disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the CycloneDX report.`)
		o.Scanners = nil
	}
}

// Remote returns options for OCI registries
func (o *Options) Remote() ftypes.RemoteOptions {
	return ftypes.RemoteOptions{
		Credentials:   o.Credentials,
		RegistryToken: o.RegistryToken,
		Insecure:      o.Insecure,
		Platform:      o.Platform,
		AWSRegion:     o.AWSOptions.Region,
	}
}

func addFlag(cmd *cobra.Command, flag *Flag) {
	if flag == nil || flag.Name == "" {
		return
	}
	var flags *pflag.FlagSet
	if flag.Persistent {
		flags = cmd.PersistentFlags()
	} else {
		flags = cmd.Flags()
	}

	switch v := flag.Value.(type) {
	case int:
		flags.IntP(flag.Name, flag.Shorthand, v, flag.Usage)
	case string:
		flags.StringP(flag.Name, flag.Shorthand, v, flag.Usage)
	case []string:
		flags.StringSliceP(flag.Name, flag.Shorthand, v, flag.Usage)
	case bool:
		flags.BoolP(flag.Name, flag.Shorthand, v, flag.Usage)
	case time.Duration:
		flags.DurationP(flag.Name, flag.Shorthand, v, flag.Usage)
	}

	if flag.Deprecated {
		flags.MarkHidden(flag.Name) // nolint: gosec
	}
}

func bind(cmd *cobra.Command, flag *Flag) error {
	if flag == nil {
		return nil
	} else if flag.Name == "" {
		// This flag is available only in trivy.yaml
		viper.SetDefault(flag.ConfigName, flag.Value)
		return nil
	}

	// Bind CLI flags
	f := cmd.Flags().Lookup(flag.Name)
	if f == nil {
		// Lookup local persistent flags
		f = cmd.PersistentFlags().Lookup(flag.Name)
	}
	if err := viper.BindPFlag(flag.ConfigName, f); err != nil {
		return xerrors.Errorf("bind flag error: %w", err)
	}

	// Bind environmental variable
	if err := bindEnv(flag); err != nil {
		return err
	}

	return nil
}

func bindEnv(flag *Flag) error {
	// We don't use viper.AutomaticEnv, so we need to add a prefix manually here.
	envName := strings.ToUpper("trivy_" + strings.ReplaceAll(flag.Name, "-", "_"))
	if err := viper.BindEnv(flag.ConfigName, envName); err != nil {
		return xerrors.Errorf("bind env error: %w", err)
	}

	// Bind env aliases
	for _, alias := range flag.Aliases {
		envAlias := strings.ToUpper("trivy_" + strings.ReplaceAll(alias.Name, "-", "_"))
		if err := viper.BindEnv(flag.ConfigName, envAlias); err != nil {
			return xerrors.Errorf("bind env error: %w", err)
		}
		if alias.Deprecated {
			if _, ok := os.LookupEnv(envAlias); ok {
				log.Logger.Warnf("'%s' is deprecated. Use '%s' instead.", envAlias, envName)
			}
		}
	}
	return nil
}

func getString(flag *Flag) string {
	return cast.ToString(getValue(flag))
}

func getStringSlice(flag *Flag) []string {
	// viper always returns a string for ENV
	// https://github.com/spf13/viper/blob/419fd86e49ef061d0d33f4d1d56d5e2a480df5bb/viper.go#L545-L553
	// and uses strings.Field to separate values (whitespace only)
	// we need to separate env values with ','
	v := cast.ToStringSlice(getValue(flag))
	switch {
	case len(v) == 0: // no strings
		return nil
	case len(v) == 1 && strings.Contains(v[0], ","): // unseparated string
		v = strings.Split(v[0], ",")
	}
	return v
}

func getInt(flag *Flag) int {
	return cast.ToInt(getValue(flag))
}

func getBool(flag *Flag) bool {
	return cast.ToBool(getValue(flag))
}

func getDuration(flag *Flag) time.Duration {
	return cast.ToDuration(getValue(flag))
}

func getValue(flag *Flag) any {
	if flag == nil {
		return nil
	}

	// First, looks for aliases in config file (trivy.yaml).
	// Note that viper.RegisterAlias cannot be used for this purpose.
	var v any
	for _, alias := range flag.Aliases {
		if alias.ConfigName == "" {
			continue
		}
		v = viper.Get(alias.ConfigName)
		if v != nil {
			log.Logger.Warnf("'%s' in config file is deprecated. Use '%s' instead.", alias.ConfigName, flag.ConfigName)
			return v
		}
	}
	return viper.Get(flag.ConfigName)
}

func (f *Flags) groups() []FlagGroup {
	var groups []FlagGroup
	// This order affects the usage message, so they are sorted by frequency of use.
	if f.ScanFlagGroup != nil {
		groups = append(groups, f.ScanFlagGroup)
	}
	if f.ReportFlagGroup != nil {
		groups = append(groups, f.ReportFlagGroup)
	}
	if f.CacheFlagGroup != nil {
		groups = append(groups, f.CacheFlagGroup)
	}
	if f.DBFlagGroup != nil {
		groups = append(groups, f.DBFlagGroup)
	}
	if f.RegistryFlagGroup != nil {
		groups = append(groups, f.RegistryFlagGroup)
	}
	if f.ImageFlagGroup != nil {
		groups = append(groups, f.ImageFlagGroup)
	}
	if f.SBOMFlagGroup != nil {
		groups = append(groups, f.SBOMFlagGroup)
	}
	if f.VulnerabilityFlagGroup != nil {
		groups = append(groups, f.VulnerabilityFlagGroup)
	}
	if f.MisconfFlagGroup != nil {
		groups = append(groups, f.MisconfFlagGroup)
	}
	if f.ModuleFlagGroup != nil {
		groups = append(groups, f.ModuleFlagGroup)
	}
	if f.SecretFlagGroup != nil {
		groups = append(groups, f.SecretFlagGroup)
	}
	if f.LicenseFlagGroup != nil {
		groups = append(groups, f.LicenseFlagGroup)
	}
	if f.RegoFlagGroup != nil {
		groups = append(groups, f.RegoFlagGroup)
	}
	if f.CloudFlagGroup != nil {
		groups = append(groups, f.CloudFlagGroup)
	}
	if f.AWSFlagGroup != nil {
		groups = append(groups, f.AWSFlagGroup)
	}
	if f.K8sFlagGroup != nil {
		groups = append(groups, f.K8sFlagGroup)
	}
	if f.RemoteFlagGroup != nil {
		groups = append(groups, f.RemoteFlagGroup)
	}
	if f.RepoFlagGroup != nil {
		groups = append(groups, f.RepoFlagGroup)
	}
	return groups
}

func (f *Flags) AddFlags(cmd *cobra.Command) {
	aliases := make(flagAliases)
	for _, group := range f.groups() {
		for _, flag := range group.Flags() {
			addFlag(cmd, flag)

			// Register flag aliases
			aliases.Add(flag)
		}
	}

	cmd.Flags().SetNormalizeFunc(aliases.NormalizeFunc())
}

func (f *Flags) Usages(cmd *cobra.Command) string {
	var usages string
	for _, group := range f.groups() {

		flags := pflag.NewFlagSet(cmd.Name(), pflag.ContinueOnError)
		lflags := cmd.LocalFlags()
		for _, flag := range group.Flags() {
			if flag == nil || flag.Name == "" {
				continue
			}
			flags.AddFlag(lflags.Lookup(flag.Name))
		}
		if !flags.HasAvailableFlags() {
			continue
		}

		usages += fmt.Sprintf("%s Flags\n", group.Name())
		usages += flags.FlagUsages() + "\n"
	}
	return strings.TrimSpace(usages)
}

func (f *Flags) Bind(cmd *cobra.Command) error {
	for _, group := range f.groups() {
		if group == nil {
			continue
		}
		for _, flag := range group.Flags() {
			if err := bind(cmd, flag); err != nil {
				return xerrors.Errorf("flag groups: %w", err)
			}
		}
	}
	return nil
}

// nolint: gocyclo
func (f *Flags) ToOptions(appVersion string, args []string, globalFlags *GlobalFlagGroup, output io.Writer) (Options, error) {
	var err error
	opts := Options{
		AppVersion:    appVersion,
		GlobalOptions: globalFlags.ToOptions(),
	}

	if f.AWSFlagGroup != nil {
		opts.AWSOptions = f.AWSFlagGroup.ToOptions()
	}

	if f.CloudFlagGroup != nil {
		opts.CloudOptions = f.CloudFlagGroup.ToOptions()
	}

	if f.CacheFlagGroup != nil {
		opts.CacheOptions, err = f.CacheFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("cache flag error: %w", err)
		}
	}

	if f.DBFlagGroup != nil {
		opts.DBOptions, err = f.DBFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("flag error: %w", err)
		}
	}

	if f.ImageFlagGroup != nil {
		opts.ImageOptions, err = f.ImageFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("image flag error: %w", err)
		}
	}

	if f.K8sFlagGroup != nil {
		opts.K8sOptions, err = f.K8sFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("k8s flag error: %w", err)
		}
	}

	if f.LicenseFlagGroup != nil {
		opts.LicenseOptions = f.LicenseFlagGroup.ToOptions()
	}

	if f.MisconfFlagGroup != nil {
		opts.MisconfOptions, err = f.MisconfFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("misconfiguration flag error: %w", err)
		}
	}

	if f.ModuleFlagGroup != nil {
		opts.ModuleOptions = f.ModuleFlagGroup.ToOptions()
	}

	if f.RegoFlagGroup != nil {
		opts.RegoOptions, err = f.RegoFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("rego flag error: %w", err)
		}
	}

	if f.RemoteFlagGroup != nil {
		opts.RemoteOptions = f.RemoteFlagGroup.ToOptions()
	}

	if f.RegistryFlagGroup != nil {
		opts.RegistryOptions, err = f.RegistryFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("registry flag error: %w", err)
		}
	}

	if f.RepoFlagGroup != nil {
		opts.RepoOptions = f.RepoFlagGroup.ToOptions()
	}

	if f.ReportFlagGroup != nil {
		opts.ReportOptions, err = f.ReportFlagGroup.ToOptions(output)
		if err != nil {
			return Options{}, xerrors.Errorf("report flag error: %w", err)
		}
	}

	if f.SBOMFlagGroup != nil {
		opts.SBOMOptions, err = f.SBOMFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("sbom flag error: %w", err)
		}
	}

	if f.ScanFlagGroup != nil {
		opts.ScanOptions, err = f.ScanFlagGroup.ToOptions(args)
		if err != nil {
			return Options{}, xerrors.Errorf("scan flag error: %w", err)
		}
	}

	if f.SecretFlagGroup != nil {
		opts.SecretOptions = f.SecretFlagGroup.ToOptions()
	}

	if f.VulnerabilityFlagGroup != nil {
		opts.VulnerabilityOptions = f.VulnerabilityFlagGroup.ToOptions()
	}

	opts.Align()

	return opts, nil
}

type flagAlias struct {
	formalName string
	deprecated bool
	once       sync.Once
}

// flagAliases have aliases for CLI flags
type flagAliases map[string]*flagAlias

func (a flagAliases) Add(flag *Flag) {
	if flag == nil {
		return
	}
	for _, alias := range flag.Aliases {
		a[alias.Name] = &flagAlias{
			formalName: flag.Name,
			deprecated: alias.Deprecated,
		}
	}
}

func (a flagAliases) NormalizeFunc() func(*pflag.FlagSet, string) pflag.NormalizedName {
	return func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if alias, ok := a[name]; ok {
			if alias.deprecated {
				// NormalizeFunc is called several times
				alias.once.Do(func() {
					log.Logger.Warnf("'--%s' is deprecated. Use '--%s' instead.", name, alias.formalName)
				})
			}
			name = alias.formalName
		}
		return pflag.NormalizedName(name)
	}
}
