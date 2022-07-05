package flag

import (
	"time"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	QuietFlag    = "quiet"
	DebugFlag    = "debug"
	InsecureFlag = "insecure"
	TimeoutFlag  = "timeout"
	CacheDirFlag = "cache-dir"
)

// GlobalFlags composes global flags
type GlobalFlags struct {
	Quiet    *bool
	Debug    *bool
	Insecure *bool
	Timeout  *time.Duration
	CacheDir *string
}

// GlobalOptions defines flags and other configuration parameters for all the subcommands
type GlobalOptions struct {
	Quiet    bool
	Debug    bool
	Insecure bool
	Timeout  time.Duration
	CacheDir string
}

func NewGlobalDefaultFlags() *GlobalFlags {
	return &GlobalFlags{
		Quiet:    lo.ToPtr(false),
		Debug:    lo.ToPtr(false),
		Insecure: lo.ToPtr(false),
		Timeout:  lo.ToPtr(time.Second * 300), // 5 mins
		CacheDir: lo.ToPtr(utils.DefaultCacheDir()),
	}
}

func (f *GlobalFlags) AddFlags(cmd *cobra.Command) {
	if f.Quiet != nil {
		cmd.PersistentFlags().BoolP(QuietFlag, "q", *f.Quiet, "suppress progress bar and log output")
		viper.BindPFlag(QuietFlag, cmd.PersistentFlags().Lookup(QuietFlag))
	}

	if f.Debug != nil {
		cmd.PersistentFlags().BoolP(DebugFlag, "d", *f.Debug, "debug mode")
		viper.BindPFlag(DebugFlag, cmd.PersistentFlags().Lookup(DebugFlag))
	}

	if f.Insecure != nil {
		cmd.PersistentFlags().Bool(InsecureFlag, *f.Insecure, "allow insecure server connections when using TLS")
		viper.BindPFlag(InsecureFlag, cmd.PersistentFlags().Lookup(InsecureFlag))
	}

	if f.Timeout != nil {
		cmd.PersistentFlags().Duration(TimeoutFlag, *f.Timeout, "timeout")
		viper.BindPFlag(TimeoutFlag, cmd.PersistentFlags().Lookup(TimeoutFlag))
	}

	if f.CacheDir != nil {
		cmd.PersistentFlags().String(CacheDirFlag, *f.CacheDir, "cache directory")
		viper.BindPFlag(CacheDirFlag, cmd.PersistentFlags().Lookup(CacheBackendFlag))
	}
}

func (f *GlobalFlags) ToOptions() GlobalOptions {
	return GlobalOptions{
		Quiet:    viper.GetBool(QuietFlag),
		Debug:    viper.GetBool(DebugFlag),
		Insecure: viper.GetBool(InsecureFlag),
		Timeout:  viper.GetDuration(TimeoutFlag),
		CacheDir: viper.GetString(CacheDirFlag),
	}
}
