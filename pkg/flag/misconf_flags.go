package flag

import (
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	FilePatternsFlag       = "file-patterns"
	IncludeNonFailuresFlag = "include-non-failures"
	SkipPolicyUpdateFlag   = "skip-policy-update"
	TraceFlag              = "trace"
	ConfigPolicyFlag       = "config-policy"
	ConfigDataFlag         = "config-data"
	PolicyNamespaceFlag    = "policy-namespaces"
)

// MisconfFlags composes common printer flag structs used for commands providing misconfinguration scanning.
type MisconfFlags struct {
	FilePatterns       *[]string
	IncludeNonFailures *bool
	SkipPolicyUpdate   *bool // deprecated
	Trace              *bool

	// Rego
	PolicyPaths      *[]string
	DataPaths        *[]string
	PolicyNamespaces *[]string
}

type MisconfOptions struct {
	FilePatterns       []string
	IncludeNonFailures bool
	SkipPolicyUpdate   bool // deprecated
	Trace              bool

	// Rego
	PolicyPaths      []string
	DataPaths        []string
	PolicyNamespaces []string
}

func NewMisconfDefaultFlags() *MisconfFlags {
	return &MisconfFlags{
		FilePatterns:       lo.ToPtr([]string{}),
		IncludeNonFailures: lo.ToPtr(false),
		SkipPolicyUpdate:   lo.ToPtr(false),
		Trace:              lo.ToPtr(false),
		PolicyPaths:        lo.ToPtr([]string{}),
		DataPaths:          lo.ToPtr([]string{}),
		PolicyNamespaces:   lo.ToPtr([]string{}),
	}
}

func (f *MisconfFlags) AddFlags(cmd *cobra.Command) {
	if f.FilePatterns != nil {
		cmd.Flags().StringSlice(FilePatternsFlag, *f.FilePatterns, "specify file patterns")
	}
	if f.IncludeNonFailures != nil {
		cmd.Flags().Bool(IncludeNonFailuresFlag, *f.IncludeNonFailures, "include successes and exceptions")
	}
	if f.SkipPolicyUpdate != nil {
		cmd.Flags().Bool(SkipPolicyUpdateFlag, *f.SkipPolicyUpdate, "deprecated")
		cmd.Flags().MarkHidden(SkipPolicyUpdateFlag)
	}
	if f.Trace != nil {
		cmd.Flags().Bool(TraceFlag, *f.Trace, "enable more verbose trace output for custom queries")
	}
	if f.PolicyPaths != nil {
		cmd.Flags().StringSlice(ConfigPolicyFlag, *f.PolicyPaths, "specify paths to the Rego policy files directory, applying config files")
		viper.RegisterAlias(ConfigPolicyFlag, "policy")
	}
	if f.DataPaths != nil {
		cmd.Flags().StringSlice(ConfigDataFlag, *f.DataPaths, "specify paths from which data for the Rego policies will be recursively loaded")
		viper.RegisterAlias(ConfigDataFlag, "data")
	}
	if f.PolicyNamespaces != nil {
		cmd.Flags().StringSlice(PolicyNamespaceFlag, *f.PolicyNamespaces, "Rego namespaces")
		viper.RegisterAlias(PolicyNamespaceFlag, "namespaces")
	}
}

func (f *MisconfFlags) ToOptions() (MisconfOptions, error) {
	skipPolicyUpdateFlag := viper.GetBool(SkipPolicyUpdateFlag)
	if skipPolicyUpdateFlag {
		log.Logger.Warn("'--skip-policy-update' is no longer necessary as the built-in policies are embedded into the binary")
	}
	return MisconfOptions{
		FilePatterns:       viper.GetStringSlice(FilePatternsFlag),
		IncludeNonFailures: viper.GetBool(IncludeNonFailuresFlag),
		Trace:              viper.GetBool(TraceFlag),

		PolicyPaths:      viper.GetStringSlice(ConfigPolicyFlag),
		DataPaths:        viper.GetStringSlice(ConfigDataFlag),
		PolicyNamespaces: viper.GetStringSlice(PolicyNamespaceFlag),
	}, nil
}
