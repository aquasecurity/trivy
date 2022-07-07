package flag

import (
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
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
}

type Flags struct {
	CacheFlags      *CacheFlags
	DBFlags         *DBFlags
	ImageFlags      *ImageFlags
	KubernetesFlags *KubernetesFlags
	MisconfFlags    *MisconfFlags
	RemoteFlags     *RemoteFlags
	ReportFlags     *ReportFlags
	SBOMFlags       *SBOMFlags
	ScanFlags       *ScanFlags
}

// Options holds all the runtime configuration
type Options struct {
	GlobalOptions
	CacheOptions
	DBOptions
	ImageOptions
	KubernetesOptions
	MisconfOptions
	RemoteOptions
	ReportOptions
	SBOMOptions
	ScanOptions

	// Trivy's version, not populated via CLI flags
	AppVersion string

	// We don't want to allow disabled analyzers to be passed by users, but it is necessary for internal use.
	DisabledAnalyzers []analyzer.Type
}

func addFlag(cmd *cobra.Command, flag *Flag) {
	if flag == nil || flag.Name == "" {
		return
	}
	switch v := flag.Value.(type) {
	case int:
		cmd.Flags().IntP(flag.Name, flag.Shorthand, v, flag.Usage)
	case string:
		cmd.Flags().StringP(flag.Name, flag.Shorthand, v, flag.Usage)
	case bool:
		cmd.Flags().BoolP(flag.Name, flag.Shorthand, v, flag.Usage)
	case time.Duration:
		cmd.Flags().DurationP(flag.Name, flag.Shorthand, v, flag.Usage)
	}
}

func bind(cmd *cobra.Command, flag *Flag) error {
	if flag == nil || flag.Name == "" {
		return nil
	}
	if err := viper.BindPFlag(flag.ConfigName, cmd.Flags().Lookup(flag.Name)); err != nil {
		return err
	}
	// We don't use viper.AutomaticEnv, so we need to add a prefix manually here.
	if err := viper.BindEnv(flag.ConfigName, "trivy_"+flag.Name); err != nil {
		return err
	}
	return nil
}

func get[T any](flag *Flag) T {
	if flag == nil {
		var zero T
		return zero
	}
	return viper.Get(flag.ConfigName).(T)
}

func (f *Flags) AddFlags(cmd *cobra.Command) {
	if f.CacheFlags != nil {
		f.CacheFlags.AddFlags(cmd)
	}
	if f.DBFlags != nil {
		f.DBFlags.AddFlags(cmd)
	}
	if f.ImageFlags != nil {
		f.ImageFlags.AddFlags(cmd)
	}
	if f.KubernetesFlags != nil {
		f.KubernetesFlags.AddFlags(cmd)
	}
	if f.MisconfFlags != nil {
		f.MisconfFlags.AddFlags(cmd)
	}
	if f.RemoteFlags != nil {
		f.RemoteFlags.AddFlags(cmd)
	}
	if f.ReportFlags != nil {
		f.ReportFlags.AddFlags(cmd)
	}
	if f.SBOMFlags != nil {
		f.SBOMFlags.AddFlags(cmd)
	}
	if f.ScanFlags != nil {
		f.ScanFlags.AddFlags(cmd)
	}

	cmd.Flags().SetNormalizeFunc(flagNameNormalize)
}

func (f *Flags) Bind(cmd *cobra.Command) error {
	if err := f.ReportFlags.Bind(cmd); err != nil {
		return err
	}
	return nil
}

func (f *Flags) ToOptions(appVersion string, args []string, globalFlags *GlobalFlags, output io.Writer) (Options, error) {
	var err error
	opts := Options{
		AppVersion:    appVersion,
		GlobalOptions: globalFlags.ToOptions(),
	}

	if f.CacheFlags != nil {
		opts.CacheOptions, err = f.CacheFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("cache flag error: %w", err)
		}
	}

	if f.DBFlags != nil {
		opts.DBOptions, err = f.DBFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("flag error: %w", err)
		}
	}

	if f.ImageFlags != nil {
		opts.ImageOptions = f.ImageFlags.ToOptions()
	}

	if f.KubernetesFlags != nil {
		opts.KubernetesOptions = f.KubernetesFlags.ToOptions()
	}

	if f.MisconfFlags != nil {
		opts.MisconfOptions, err = f.MisconfFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("misconfiguration flag error: %w", err)
		}
	}

	if f.RemoteFlags != nil {
		opts.RemoteOptions = f.RemoteFlags.ToOptions()
	}

	if f.ReportFlags != nil {
		opts.ReportOptions, err = f.ReportFlags.ToOptions(output)
		if err != nil {
			return Options{}, xerrors.Errorf("report flag error: %w", err)
		}
	}

	if f.SBOMFlags != nil {
		opts.SBOMOptions, err = f.SBOMFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("sbom flag error: %w", err)
		}
	}

	if f.ScanFlags != nil {
		opts.ScanOptions = f.ScanFlags.ToOptions(args)
	}

	return opts, nil
}

func flagNameNormalize(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "skip-update":
		name = SkipDBUpdateFlag
	case "policy":
		name = ConfigPolicyFlag
	case "data":
		name = ConfigDataFlag
	case "namespaces":
		name = PolicyNamespaceFlag
	case "ctx":
		name = ClusterContextFlag
	}
	return pflag.NormalizedName(name)
}
