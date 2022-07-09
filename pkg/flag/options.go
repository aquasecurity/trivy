package flag

import (
	"io"
	"strings"
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

	// Persistent represents if the flag is persistent
	Persistent bool
}

type FlagGroup interface {
	AddFlags(cmd *cobra.Command)
	Bind(cmd *cobra.Command) error
}

type Flags struct {
	CacheFlagGroup   *CacheFlagGroup
	DBFlagGroup      *DBFlagGroup
	ImageFlagGroup   *ImageFlagGroup
	K8sFlagGroup     *K8sFlagGroup
	MisconfFlagGroup *MisconfFlagGroup
	RemoteFlagGroup  *RemoteFlagGroup
	ReportFlagGroup  *ReportFlagGroup
	SBOMFlagGroup    *SBOMFlagGroup
	ScanFlagGroup    *ScanFlagGroup
}

// Options holds all the runtime configuration
type Options struct {
	GlobalOptions
	CacheOptions
	DBOptions
	ImageOptions
	K8sOptions
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
		if flag.Persistent {
			cmd.PersistentFlags().IntP(flag.Name, flag.Shorthand, v, flag.Usage)
		} else {
			cmd.Flags().IntP(flag.Name, flag.Shorthand, v, flag.Usage)
		}
	case string:
		if flag.Persistent {
			cmd.PersistentFlags().StringP(flag.Name, flag.Shorthand, v, flag.Usage)
		} else {
			cmd.Flags().StringP(flag.Name, flag.Shorthand, v, flag.Usage)
		}
	case []string:
		if flag.Persistent {
			cmd.PersistentFlags().StringSliceP(flag.Name, flag.Shorthand, v, flag.Usage)
		} else {
			cmd.Flags().StringSliceP(flag.Name, flag.Shorthand, v, flag.Usage)
		}
	case bool:
		if flag.Persistent {
			cmd.PersistentFlags().BoolP(flag.Name, flag.Shorthand, v, flag.Usage)
		} else {
			cmd.Flags().BoolP(flag.Name, flag.Shorthand, v, flag.Usage)
		}
	case time.Duration:
		if flag.Persistent {
			cmd.PersistentFlags().DurationP(flag.Name, flag.Shorthand, v, flag.Usage)
		} else {
			cmd.PersistentFlags().DurationP(flag.Name, flag.Shorthand, v, flag.Usage)
		}
	}
}

func bind(cmd *cobra.Command, flag *Flag) error {
	if flag == nil || flag.Name == "" {
		return nil
	}
	if flag.Persistent {
		if err := viper.BindPFlag(flag.ConfigName, cmd.PersistentFlags().Lookup(flag.Name)); err != nil {
			return err
		}
	} else {
		if err := viper.BindPFlag(flag.ConfigName, cmd.Flags().Lookup(flag.Name)); err != nil {
			return err
		}
	}
	// We don't use viper.AutomaticEnv, so we need to add a prefix manually here.
	if err := viper.BindEnv(flag.ConfigName, strings.ToUpper("trivy_"+flag.Name)); err != nil {
		return err
	}
	return nil
}

func getString(flag *Flag) string {
	if flag == nil {
		return ""
	}
	return viper.GetString(flag.ConfigName)
}

func getStringSlice(flag *Flag) []string {
	if flag == nil {
		return nil
	}
	return viper.GetStringSlice(flag.ConfigName)
}

func getInt(flag *Flag) int {
	if flag == nil {
		return 0
	}
	return viper.GetInt(flag.ConfigName)
}

func getBool(flag *Flag) bool {
	if flag == nil {
		return false
	}
	return viper.GetBool(flag.ConfigName)
}

func getDuration(flag *Flag) time.Duration {
	if flag == nil {
		return 0
	}
	return viper.GetDuration(flag.ConfigName)
}

func (f *Flags) groups() []FlagGroup {
	var groups []FlagGroup
	if f.CacheFlagGroup != nil {
		groups = append(groups, f.CacheFlagGroup)
	}
	if f.DBFlagGroup != nil {
		groups = append(groups, f.DBFlagGroup)
	}
	if f.ImageFlagGroup != nil {
		groups = append(groups, f.ImageFlagGroup)
	}
	if f.K8sFlagGroup != nil {
		groups = append(groups, f.K8sFlagGroup)
	}
	if f.MisconfFlagGroup != nil {
		groups = append(groups, f.MisconfFlagGroup)
	}
	if f.RemoteFlagGroup != nil {
		groups = append(groups, f.RemoteFlagGroup)
	}
	if f.ReportFlagGroup != nil {
		groups = append(groups, f.ReportFlagGroup)
	}
	if f.SBOMFlagGroup != nil {
		groups = append(groups, f.SBOMFlagGroup)
	}
	if f.ScanFlagGroup != nil {
		groups = append(groups, f.ScanFlagGroup)
	}
	return groups
}

func (f *Flags) AddFlags(cmd *cobra.Command) {
	for _, group := range f.groups() {
		if group == nil {
			continue
		}
		group.AddFlags(cmd)
	}

	cmd.Flags().SetNormalizeFunc(flagNameNormalize)
}

func (f *Flags) Bind(cmd *cobra.Command) error {
	for _, group := range f.groups() {
		if group == nil {
			continue
		}
		if err := group.Bind(cmd); err != nil {
			return xerrors.Errorf("flag groups: %w", err)
		}
	}
	return nil
}

func (f *Flags) ToOptions(appVersion string, args []string, globalFlags *GlobalFlagGroup, output io.Writer) (Options, error) {
	var err error
	opts := Options{
		AppVersion:    appVersion,
		GlobalOptions: globalFlags.ToOptions(),
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
		opts.ImageOptions = f.ImageFlagGroup.ToOptions()
	}

	if f.K8sFlagGroup != nil {
		opts.K8sOptions = f.K8sFlagGroup.ToOptions()
	}

	if f.MisconfFlagGroup != nil {
		opts.MisconfOptions, err = f.MisconfFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("misconfiguration flag error: %w", err)
		}
	}

	if f.RemoteFlagGroup != nil {
		opts.RemoteOptions = f.RemoteFlagGroup.ToOptions()
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
		opts.ScanOptions = f.ScanFlagGroup.ToOptions(args)
	}

	return opts, nil
}

func flagNameNormalize(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "skip-update":
		name = SkipDBUpdateFlag.Name
	case "policy":
		name = ConfigPolicyFlag.Name
	case "data":
		name = ConfigDataFlag.Name
	case "namespaces":
		name = PolicyNamespaceFlag.Name
	case "ctx":
		name = ClusterContextFlag.Name
	}
	return pflag.NormalizedName(name)
}
