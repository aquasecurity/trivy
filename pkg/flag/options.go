package flag

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/samber/lo"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

type FlagType interface {
	int | string | []string | bool | time.Duration | float64 | map[string][]string
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

	// Persistent represents if the flag is persistent.
	Persistent bool

	// Deprecated represents if the flag is deprecated.
	// It shows a warning message when the flag is used.
	Deprecated string

	// Removed represents if the flag is removed and no longer works.
	// It shows an error message when the flag is used.
	Removed string

	// Internal represents if the flag is for internal use only.
	// It is not shown in the usage message.
	Internal bool

	// Aliases represents aliases
	Aliases []Alias

	// TelemetrySafe indicates if the flag value is safe to be included in telemetry.
	TelemetrySafe bool

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

	if f.Deprecated != "" && f.isSet() {
		log.Warnf(`"--%s" is deprecated. %s`, f.Name, f.Deprecated)
	}
	if f.Removed != "" && f.isSet() {
		log.Errorf(`"--%s" was removed. %s`, f.Name, f.Removed)
		return xerrors.Errorf(`removed flag ("--%s")`, f.Name)
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
			log.Warnf("'%s' in config file is deprecated. Use '%s' instead.", alias.ConfigName, f.ConfigName)
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
	case map[string][]string:
		return cast.ToStringMapStringSlice(val)
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

func (f *Flag[T]) GetConfigName() string {
	return f.ConfigName
}

func (f *Flag[T]) GetDefaultValue() any {
	return f.Default
}

func (f *Flag[T]) GetAliases() []Alias {
	return f.Aliases
}

func (f *Flag[T]) IsTelemetrySafe() bool {
	return f.TelemetrySafe
}

func (f *Flag[T]) IsSet() bool {
	if f == nil {
		return false
	}
	return f.isSet()
}

func (f *Flag[T]) Hidden() bool {
	return f.Deprecated != "" || f.Removed != "" || f.Internal
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
			if len(f.Values) <= 4 {
				// Display inline for a small number of choices
				usage += fmt.Sprintf(" (allowed values: %s)", strings.Join(f.Values, ","))
			} else {
				// Display as a bullet list for many choices
				usage += "\nAllowed values:"
				for _, val := range f.Values {
					usage += fmt.Sprintf("\n  - %s", val)
				}
				if v != "" {
					usage += "\n"
				}
			}
		}
		flags.StringP(f.Name, f.Shorthand, v, usage)
	case []string:
		usage := f.Usage
		if len(f.Values) > 0 {
			if len(f.Values) <= 4 {
				// Display inline for a small number of choices
				usage += fmt.Sprintf(" (allowed values: %s)", strings.Join(f.Values, ","))
			} else {
				// Display as a bullet list for many choices
				usage += "\nAllowed values:"
				for _, val := range f.Values {
					usage += fmt.Sprintf("\n  - %s", val)
				}
				if len(v) != 0 {
					usage += "\n"
				}
			}
		}
		flags.StringSliceP(f.Name, f.Shorthand, v, usage)
	case bool:
		flags.BoolP(f.Name, f.Shorthand, v, f.Usage)
	case time.Duration:
		flags.DurationP(f.Name, f.Shorthand, v, f.Usage)
	case float64:
		flags.Float64P(f.Name, f.Shorthand, v, f.Usage)
	}

	if f.Hidden() {
		_ = flags.MarkHidden(f.Name)
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
	if flag == nil {
		// Lookup local persistent flags
		flag = cmd.PersistentFlags().Lookup(f.Name)
	}
	if err := viper.BindPFlag(f.ConfigName, flag); err != nil {
		return xerrors.Errorf("bind flag error: %w", err)
	}

	// Bind environmental variable
	return f.BindEnv()
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
				log.Warnf("'%s' is deprecated. Use '%s' instead.", envAlias, envName)
			}
		}
	}
	return nil
}

type FlagGroup interface {
	Name() string
	Flags() []Flagger
	ToOptions(*Options) error
}

type Flagger interface {
	GetName() string
	GetConfigName() string
	GetDefaultValue() any
	GetAliases() []Alias
	Hidden() bool
	IsTelemetrySafe() bool
	IsSet() bool

	Parse() error
	Add(cmd *cobra.Command)
	Bind(cmd *cobra.Command) error
}

type Flags []FlagGroup

// Options holds all the runtime configuration
type Options struct {
	GlobalOptions
	AWSOptions
	CacheOptions
	CleanOptions
	DBOptions
	ImageOptions
	K8sOptions
	LicenseOptions
	MisconfOptions
	ModuleOptions
	PackageOptions
	RegistryOptions
	RegoOptions
	RemoteOptions
	RepoOptions
	ReportOptions
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

	// args is the arguments passed to the command.
	args []string

	// usedFlags allows us to get the underlying flags for the options
	usedFlags []Flagger
}

// Align takes consistency of options
func (o *Options) Align(f *Flags) error {
	if scanFlagGroup, ok := findFlagGroup[*ScanFlagGroup](f); ok && scanFlagGroup.Scanners != nil {
		o.enableSBOM()
	}

	if packageFlagGroup, ok := findFlagGroup[*PackageFlagGroup](f); ok &&
		packageFlagGroup.PkgRelationships != nil &&
		slices.Compare(o.PkgRelationships, ftypes.Relationships) != 0 &&
		(o.DependencyTree || slices.Contains(types.SupportedSBOMFormats, o.Format) || len(o.VEXSources) != 0) {
		return xerrors.Errorf("'--pkg-relationships' cannot be used with '--dependency-tree', '--vex' or SBOM formats")
	}

	if o.Compliance.Spec.ID != "" {
		if viper.IsSet(ScannersFlag.ConfigName) {
			log.Info(`The option to change scanners is disabled for scanning with the "--compliance" flag. Default scanners used.`)
		}
		if viper.IsSet(ImageConfigScannersFlag.ConfigName) {
			log.Info(`The option to change image config scanners is disabled for scanning with the "--compliance" flag. Default image config scanners used.`)
		}

		// set scanners types by spec
		scanners, err := o.Compliance.Scanners()
		if err != nil {
			return xerrors.Errorf("scanner error: %w", err)
		}

		o.Scanners = scanners
		o.ImageConfigScanners = nil
		// TODO: define image-config-scanners in the spec
		if o.Compliance.Spec.ID == types.ComplianceDockerCIS160 {
			o.Scanners = types.Scanners{types.VulnerabilityScanner}
			o.ImageConfigScanners = types.Scanners{
				types.MisconfigScanner,
				types.SecretScanner,
			}
		}
	}

	return nil
}

func (o *Options) enableSBOM() {
	// Always need packages when the vulnerability scanner is enabled
	if o.Scanners.Enabled(types.VulnerabilityScanner) {
		o.Scanners.Enable(types.SBOMScanner)
	}

	// Enable the SBOM scanner when a list of packages is necessary.
	if o.ListAllPkgs || slices.Contains(types.SupportedSBOMFormats, o.Format) {
		o.Scanners.Enable(types.SBOMScanner)
	}

	if o.Format == types.FormatCycloneDX || o.Format == types.FormatSPDX || o.Format == types.FormatSPDXJSON {
		// Vulnerability scanning is disabled by default for CycloneDX.
		if !viper.IsSet(ScannersFlag.ConfigName) {
			log.Info(fmt.Sprintf(`"--format %[1]s" disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the "%[1]s" report.`, o.Format))
			o.Scanners = nil
		}
		o.Scanners.Enable(types.SBOMScanner)
	}
}

// ScanOpts returns options for scanning
func (o *Options) ScanOpts() types.ScanOptions {
	return types.ScanOptions{
		PkgTypes:            o.PkgTypes,
		PkgRelationships:    o.PkgRelationships,
		Scanners:            o.Scanners,
		ImageConfigScanners: o.ImageConfigScanners, // this is valid only for 'image' subcommand
		ScanRemovedPackages: o.ScanRemovedPkgs,     // this is valid only for 'image' subcommand
		LicenseCategories:   o.LicenseCategories,
		LicenseFull:         o.LicenseFull,
		FilePatterns:        o.FilePatterns,
		IncludeDevDeps:      o.IncludeDevDeps,
		Distro:              o.Distro,
		VulnSeveritySources: o.VulnSeveritySources,
	}
}

// RegistryOpts returns options for OCI registries
func (o *Options) RegistryOpts() ftypes.RegistryOptions {
	return ftypes.RegistryOptions{
		Credentials:     o.Credentials,
		RegistryToken:   o.RegistryToken,
		Insecure:        o.Insecure,
		Platform:        o.Platform,
		AWSRegion:       o.AWSOptions.Region,
		RegistryMirrors: o.RegistryMirrors,
	}
}

// FilterOpts returns options for filtering
func (o *Options) FilterOpts() result.FilterOptions {
	return result.FilterOptions{
		Severities:         o.Severities,
		IgnoreStatuses:     o.IgnoreStatuses,
		IncludeNonFailures: o.IncludeNonFailures,
		IgnoreFile:         o.IgnoreFile,
		PolicyFile:         o.IgnorePolicy,
		IgnoreLicenses:     o.IgnoredLicenses,
		CacheDir:           o.CacheDir,
		VEXSources:         o.VEXSources,
	}
}

// CacheOpts returns options for scan cache
func (o *Options) CacheOpts() cache.Options {
	return cache.Options{
		Backend:     o.CacheBackend,
		CacheDir:    o.CacheDir,
		RedisCACert: o.RedisCACert,
		RedisCert:   o.RedisCert,
		RedisKey:    o.RedisKey,
		RedisTLS:    o.RedisTLS,
		TTL:         o.CacheTTL,
	}
}

// RemoteCacheOpts returns options for remote scan cache
func (o *Options) RemoteCacheOpts() cache.RemoteOptions {
	return cache.RemoteOptions{
		ServerAddr:    o.ServerAddr,
		CustomHeaders: o.CustomHeaders,
		PathPrefix:    o.PathPrefix,
	}
}

func (o *Options) ClientScannerOpts() client.ServiceOption {
	return client.ServiceOption{
		RemoteURL:     o.ServerAddr,
		CustomHeaders: o.CustomHeaders,
		Insecure:      o.Insecure,
		PathPrefix:    o.PathPrefix,
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

// GetUsedFlags returns the explicitly set flags for the options.
func (o *Options) GetUsedFlags() []Flagger {
	return o.usedFlags
}

func (o *Options) outputPluginWriter(ctx context.Context) (writer io.Writer, cleanup func() error, err error) {
	pluginName := strings.TrimPrefix(o.Output, "plugin=")

	pr, pw := io.Pipe()

	// Close pipes on error
	defer func() {
		if err != nil {
			if pr != nil {
				pr.Close()
			}
			if pw != nil {
				pw.Close()
			}
		}
	}()

	wait, err := plugin.Start(ctx, pluginName, plugin.Options{
		Args:  o.OutputPluginArgs,
		Stdin: pr,
	})
	if err != nil {
		return nil, nil, xerrors.Errorf("plugin start: %w", err)
	}

	cleanup = func() error {
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
	return lo.Filter(*f, func(group FlagGroup, _ int) bool {
		return group != nil && group.Name() != "Global"
	})
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
	opts := Options{
		AppVersion: app.Version(),
		args:       args,
	}

	for _, group := range *f { // Include global flags
		if err := parseFlags(group); err != nil {
			return Options{}, xerrors.Errorf("unable to parse flags: %w", err)
		}

		opts.usedFlags = append(opts.usedFlags, usedFlags(group)...)

		if err := group.ToOptions(&opts); err != nil {
			return Options{}, xerrors.Errorf("unable to convert flags to options: %w", err)
		}
	}

	if err := opts.Align(f); err != nil {
		return Options{}, xerrors.Errorf("align options error: %w", err)
	}

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
					log.Warnf("'--%s' is deprecated. Use '--%s' instead.", name, alias.formalName)
				})
			}
			name = alias.formalName
		}
		return pflag.NormalizedName(name)
	}
}

func HiddenFlags() []string {
	var allFlagGroups = []FlagGroup{
		NewGlobalFlagGroup(),
		NewCacheFlagGroup(),
		NewCleanFlagGroup(),
		NewClientFlags(),
		NewDBFlagGroup(),
		NewImageFlagGroup(),
		NewK8sFlagGroup(),
		NewLicenseFlagGroup(),
		NewMisconfFlagGroup(),
		NewModuleFlagGroup(),
		NewPackageFlagGroup(),
		NewRegistryFlagGroup(),
		NewRegoFlagGroup(),
		NewReportFlagGroup(),
		NewRepoFlagGroup(),
		NewScanFlagGroup(),
		NewSecretFlagGroup(),
		NewServerFlags(),
		NewVulnerabilityFlagGroup(),
	}

	var hiddenFlags []string
	for _, flagGroup := range allFlagGroups {
		for _, flag := range flagGroup.Flags() {
			if !reflect.ValueOf(flag).IsNil() && flag.Hidden() {
				hiddenFlags = append(hiddenFlags, flag.GetConfigName())
			}
		}
	}
	return hiddenFlags
}

// findFlagGroup finds a flag group by type T
// Note that Go generics doesn't support methods today.
// cf. https://github.com/golang/go/issues/49085
func findFlagGroup[T FlagGroup](f *Flags) (T, bool) {
	for _, group := range *f {
		if g, ok := group.(T); ok {
			return g, true
		}
	}
	var zero T
	return zero, false
}

// usedFlags returns a slice of flags that are set in the given FlagGroup.
func usedFlags(fg FlagGroup) []Flagger {
	if fg == nil || fg.Flags() == nil {
		return nil
	}

	var flags []Flagger
	for _, flag := range fg.Flags() {
		if flag == nil {
			continue
		}
		if flag.IsSet() {
			flags = append(flags, flag)
		}
	}
	return flags
}
