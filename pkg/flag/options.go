package flag

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/samber/lo"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version"
)

type FlagType interface {
	int | string | []string | bool | time.Duration | float64
}

type Flag[T FlagType] struct {
	// Name is for CLI flag and environment variable.
	// If this field is empty, it will be available only in config file.
	Name string

	// ConfigName is a key in config file. It is also used as a key of viper.
	ConfigName string

	// Shorthand is a shorthand letter.
	Shorthand string

	// Default is the default value. It should be defined when the value is different from the zero value.
	Default T

	// Values is a list of allowed values.
	// It currently supports string flags and string slice flags only.
	Values []string

	// ValueNormalize is a function to normalize the value.
	// It can be used for aliases, etc.
	ValueNormalize func(T) T

	// Usage explains how to use the flag.
	Usage string

	// Persistent represents if the flag is persistent
	Persistent bool

	// Deprecated represents if the flag is deprecated
	Deprecated bool

	// Aliases represents aliases
	Aliases []Alias

	// value is the value passed through CLI flag, env, or config file.
	// It is populated after flag.Parse() is called.
	value T
}

type Alias struct {
	Name       string
	ConfigName string
	Deprecated bool
}

func (f *Flag[T]) Clone() *Flag[T] {
	var t T
	ff := *f
	ff.value = t
	fff := &ff
	return fff
}

func (f *Flag[T]) Parse() error {
	if f == nil {
		return nil
	}

	v := f.parse()
	if v == nil {
		f.value = lo.Empty[T]()
		return nil
	}

	value, ok := f.cast(v).(T)
	if !ok {
		return xerrors.Errorf("failed to parse flag %s", f.Name)
	}

	if f.ValueNormalize != nil {
		value = f.ValueNormalize(value)
	}

	if f.isSet() && !f.allowedValue(value) {
		return xerrors.Errorf(`invalid argument "%s" for "--%s" flag: must be one of %q`, value, f.Name, f.Values)
	}

	f.value = value
	return nil
}

func (f *Flag[T]) parse() any {
	// First, looks for aliases in config file (trivy.yaml).
	// Note that viper.RegisterAlias cannot be used for this purpose.
	var v any
	for _, alias := range f.Aliases {
		if alias.ConfigName == "" {
			continue
		}
		v = viper.Get(alias.ConfigName)
		if v != nil {
			log.Logger.Warnf("'%s' in config file is deprecated. Use '%s' instead.", alias.ConfigName, f.ConfigName)
			return v
		}
	}
	return viper.Get(f.ConfigName)
}

// cast converts the value to the type of the flag.
func (f *Flag[T]) cast(val any) any {
	switch any(f.Default).(type) {
	case bool:
		return cast.ToBool(val)
	case string:
		return cast.ToString(val)
	case int:
		return cast.ToInt(val)
	case float64, float32:
		return cast.ToFloat64(val)
	case time.Duration:
		return cast.ToDuration(val)
	case []string:
		if s, ok := val.(string); ok && strings.Contains(s, ",") {
			// Split environmental variables by comma as it is not done by viper.
			// cf. https://github.com/spf13/viper/issues/380
			// It is split by spaces only.
			// https://github.com/spf13/cast/blob/48ddde5701366ade1d3aba346e09bb58430d37c6/caste.go#L1296-L1297
			val = strings.Split(s, ",")
		}
		return cast.ToStringSlice(val)
	}
	return val
}

func (f *Flag[T]) isSet() bool {
	configNames := lo.FilterMap(f.Aliases, func(alias Alias, _ int) (string, bool) {
		return alias.ConfigName, alias.ConfigName != ""
	})
	configNames = append(configNames, f.ConfigName)

	return lo.SomeBy(configNames, viper.IsSet)
}

func (f *Flag[T]) allowedValue(v any) bool {
	if len(f.Values) == 0 {
		return true
	}
	switch value := v.(type) {
	case string:
		return slices.Contains(f.Values, value)
	case []string:
		for _, v := range value {
			if !slices.Contains(f.Values, v) {
				return false
			}
		}
	}
	return true
}

func (f *Flag[T]) GetName() string {
	return f.Name
}

func (f *Flag[T]) GetAliases() []Alias {
	return f.Aliases
}

func (f *Flag[T]) Value() (t T) {
	if f == nil {
		return t
	}
	return f.value
}

func (f *Flag[T]) Add(cmd *cobra.Command) {
	if f == nil || f.Name == "" {
		return
	}
	var flags *pflag.FlagSet
	if f.Persistent {
		flags = cmd.PersistentFlags()
	} else {
		flags = cmd.Flags()
	}

	switch v := any(f.Default).(type) {
	case int:
		flags.IntP(f.Name, f.Shorthand, v, f.Usage)
	case string:
		usage := f.Usage
		if len(f.Values) > 0 {
			usage += fmt.Sprintf(" (%s)", strings.Join(f.Values, ","))
		}
		flags.StringP(f.Name, f.Shorthand, v, usage)
	case []string:
		usage := f.Usage
		if len(f.Values) > 0 {
			usage += fmt.Sprintf(" (%s)", strings.Join(f.Values, ","))
		}
		flags.StringSliceP(f.Name, f.Shorthand, v, usage)
	case bool:
		flags.BoolP(f.Name, f.Shorthand, v, f.Usage)
	case time.Duration:
		flags.DurationP(f.Name, f.Shorthand, v, f.Usage)
	case float64:
		flags.Float64P(f.Name, f.Shorthand, v, f.Usage)
	}

	if f.Deprecated {
		flags.MarkHidden(f.Name) // nolint: gosec
	}
}

func (f *Flag[T]) Bind(cmd *cobra.Command) error {
	if f == nil {
		return nil
	} else if f.Name == "" {
		// This flag is available only in trivy.yaml
		viper.SetDefault(f.ConfigName, f.Default)
		return nil
	}

	// Bind CLI flags
	flag := cmd.Flags().Lookup(f.Name)
	if f == nil {
		// Lookup local persistent flags
		flag = cmd.PersistentFlags().Lookup(f.Name)
	}
	if err := viper.BindPFlag(f.ConfigName, flag); err != nil {
		return xerrors.Errorf("bind flag error: %w", err)
	}

	// Bind environmental variable
	if err := f.BindEnv(); err != nil {
		return err
	}

	return nil
}

func (f *Flag[T]) BindEnv() error {
	// We don't use viper.AutomaticEnv, so we need to add a prefix manually here.
	envName := strings.ToUpper("trivy_" + strings.ReplaceAll(f.Name, "-", "_"))
	if err := viper.BindEnv(f.ConfigName, envName); err != nil {
		return xerrors.Errorf("bind env error: %w", err)
	}

	// Bind env aliases
	for _, alias := range f.Aliases {
		envAlias := strings.ToUpper("trivy_" + strings.ReplaceAll(alias.Name, "-", "_"))
		if err := viper.BindEnv(f.ConfigName, envAlias); err != nil {
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

type FlagGroup interface {
	Name() string
	Flags() []Flagger
}

type Flagger interface {
	GetName() string
	GetAliases() []Alias

	Parse() error
	Add(cmd *cobra.Command)
	Bind(cmd *cobra.Command) error
}

type Flags struct {
	GlobalFlagGroup        *GlobalFlagGroup
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

	// outputWriter is not initialized via the CLI.
	// It is mainly used for testing purposes or by tools that use Trivy as a library.
	outputWriter io.Writer
}

// Align takes consistency of options
func (o *Options) Align() {
	if o.Format == types.FormatSPDX || o.Format == types.FormatSPDXJSON {
		log.Logger.Info(`"--format spdx" and "--format spdx-json" disable security scanning`)
		o.Scanners = nil
	}

	// Vulnerability scanning is disabled by default for CycloneDX.
	if o.Format == types.FormatCycloneDX && !viper.IsSet(ScannersFlag.ConfigName) && len(o.K8sOptions.Components) == 0 { // remove K8sOptions.Components validation check when vuln scan is supported for k8s report with cycloneDX
		log.Logger.Info(`"--format cyclonedx" disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the CycloneDX report.`)
		o.Scanners = nil
	}

	if o.Format == types.FormatCycloneDX && len(o.K8sOptions.Components) > 0 {
		log.Logger.Info(`"k8s with --format cyclonedx" disable security scanning`)
		o.Scanners = nil
	}
}

// RegistryOpts returns options for OCI registries
func (o *Options) RegistryOpts() ftypes.RegistryOptions {
	return ftypes.RegistryOptions{
		Credentials:   o.Credentials,
		RegistryToken: o.RegistryToken,
		Insecure:      o.Insecure,
		Platform:      o.Platform,
		AWSRegion:     o.AWSOptions.Region,
	}
}

// FilterOpts returns options for filtering
func (o *Options) FilterOpts() result.FilterOption {
	return result.FilterOption{
		Severities:         o.Severities,
		IgnoreStatuses:     o.IgnoreStatuses,
		IncludeNonFailures: o.IncludeNonFailures,
		IgnoreFile:         o.IgnoreFile,
		PolicyFile:         o.IgnorePolicy,
		IgnoreLicenses:     o.IgnoredLicenses,
		VEXPath:            o.VEXPath,
	}
}

// SetOutputWriter sets an output writer.
func (o *Options) SetOutputWriter(w io.Writer) {
	o.outputWriter = w
}

// OutputWriter returns an output writer.
// If the output file is not specified, it returns os.Stdout.
func (o *Options) OutputWriter(ctx context.Context) (io.Writer, func() error, error) {
	cleanup := func() error { return nil }
	switch {
	case o.outputWriter != nil:
		return o.outputWriter, cleanup, nil
	case o.Output == "":
		return os.Stdout, cleanup, nil
	case strings.HasPrefix(o.Output, "plugin="):
		return o.outputPluginWriter(ctx)
	}

	f, err := os.Create(o.Output)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to create output file: %w", err)
	}
	return f, f.Close, nil
}

func (o *Options) outputPluginWriter(ctx context.Context) (io.Writer, func() error, error) {
	pluginName := strings.TrimPrefix(o.Output, "plugin=")

	pr, pw := io.Pipe()
	wait, err := plugin.Start(ctx, pluginName, plugin.RunOptions{
		Args:  o.OutputPluginArgs,
		Stdin: pr,
	})
	if err != nil {
		return nil, nil, xerrors.Errorf("plugin start: %w", err)
	}

	cleanup := func() error {
		if err = pw.Close(); err != nil {
			return xerrors.Errorf("failed to close pipe: %w", err)
		}
		if err = wait(); err != nil {
			return xerrors.Errorf("plugin error: %w", err)
		}
		return nil
	}
	return pw, cleanup, nil
}

// groups returns all the flag groups other than global flags
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
			if lo.IsNil(flag) || flag.GetName() == "" {
				continue
			}
			// Register the CLI flag
			flag.Add(cmd)

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
			if lo.IsNil(flag) || flag.GetName() == "" {
				continue
			}
			flags.AddFlag(lflags.Lookup(flag.GetName()))
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
			if err := flag.Bind(cmd); err != nil {
				return xerrors.Errorf("flag groups: %w", err)
			}
		}
	}
	return nil
}

// nolint: gocyclo
func (f *Flags) ToOptions(args []string) (Options, error) {
	var err error
	opts := Options{
		AppVersion: version.AppVersion(),
	}

	if f.GlobalFlagGroup != nil {
		opts.GlobalOptions, err = f.GlobalFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("global flag error: %w", err)
		}
	}

	if f.AWSFlagGroup != nil {
		opts.AWSOptions, err = f.AWSFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("aws flag error: %w", err)
		}
	}

	if f.CloudFlagGroup != nil {
		opts.CloudOptions, err = f.CloudFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("cloud flag error: %w", err)
		}
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
			return Options{}, xerrors.Errorf("db flag error: %w", err)
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
		opts.LicenseOptions, err = f.LicenseFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("license flag error: %w", err)
		}
	}

	if f.MisconfFlagGroup != nil {
		opts.MisconfOptions, err = f.MisconfFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("misconfiguration flag error: %w", err)
		}
	}

	if f.ModuleFlagGroup != nil {
		opts.ModuleOptions, err = f.ModuleFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("module flag error: %w", err)
		}
	}

	if f.RegoFlagGroup != nil {
		opts.RegoOptions, err = f.RegoFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("rego flag error: %w", err)
		}
	}

	if f.RemoteFlagGroup != nil {
		opts.RemoteOptions, err = f.RemoteFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("remote flag error: %w", err)
		}
	}

	if f.RegistryFlagGroup != nil {
		opts.RegistryOptions, err = f.RegistryFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("registry flag error: %w", err)
		}
	}

	if f.RepoFlagGroup != nil {
		opts.RepoOptions, err = f.RepoFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("rego flag error: %w", err)
		}
	}

	if f.ReportFlagGroup != nil {
		opts.ReportOptions, err = f.ReportFlagGroup.ToOptions()
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
		opts.SecretOptions, err = f.SecretFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("secret flag error: %w", err)
		}
	}

	if f.VulnerabilityFlagGroup != nil {
		opts.VulnerabilityOptions, err = f.VulnerabilityFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("vulnerability flag error: %w", err)
		}
	}

	opts.Align()

	return opts, nil
}

func parseFlags(fg FlagGroup) error {
	for _, flag := range fg.Flags() {
		if err := flag.Parse(); err != nil {
			return xerrors.Errorf("unable to parse flag: %w", err)
		}
	}
	return nil
}

type flagAlias struct {
	formalName string
	deprecated bool
	once       sync.Once
}

// flagAliases have aliases for CLI flags
type flagAliases map[string]*flagAlias

func (a flagAliases) Add(flag Flagger) {
	for _, alias := range flag.GetAliases() {
		a[alias.Name] = &flagAlias{
			formalName: flag.GetName(),
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
