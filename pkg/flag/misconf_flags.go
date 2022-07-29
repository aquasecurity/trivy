package flag

import (
	"github.com/aquasecurity/trivy/pkg/log"
)

// e.g. config yaml
// misconfiguration:
//   trace: true
//   config-policy: "custom-policy/policy"
//   policy-namespaces: "user"
var (
	FilePatternsFlag = Flag{
		Name:       "file-patterns",
		ConfigName: "misconfiguration.file-patterns",
		Value:      []string{},
		Usage:      "specify additional config file mathcing in regex format, available with '--security-checks config'",
	}
	IncludeNonFailuresFlag = Flag{
		Name:       "include-non-failures",
		ConfigName: "misconfiguration.include-non-failures",
		Value:      false,
		Usage:      "include successes and exceptions, available with '--security-checks config'",
	}
	SkipPolicyUpdateFlag = Flag{
		Name:       "skip-policy-update",
		ConfigName: "misconfiguration.skip-policy-update",
		Value:      false,
		Usage:      "deprecated",
		Deprecated: true,
	}
	TraceFlag = Flag{
		Name:       "trace",
		ConfigName: "misconfiguration.trace",
		Value:      false,
		Usage:      "enable more verbose trace output for custom queries",
	}
	ConfigPolicyFlag = Flag{
		Name:       "config-policy",
		ConfigName: "misconfiguration.policy",
		Value:      []string{},
		Usage:      "specify paths to the Rego policy files directory, applying config files",
	}
	ConfigDataFlag = Flag{
		Name:       "config-data",
		ConfigName: "misconfiguration.data",
		Value:      []string{},
		Usage:      "specify paths from which data for the Rego policies will be recursively loaded",
	}
	PolicyNamespaceFlag = Flag{
		Name:       "policy-namespaces",
		ConfigName: "misconfiguration.namespaces",
		Value:      []string{},
		Usage:      "Rego namespaces",
	}
)

// MisconfFlagGroup composes common printer flag structs used for commands providing misconfinguration scanning.
type MisconfFlagGroup struct {
	FilePatterns       *Flag
	IncludeNonFailures *Flag
	SkipPolicyUpdate   *Flag // deprecated
	Trace              *Flag

	// Rego
	PolicyPaths      *Flag
	DataPaths        *Flag
	PolicyNamespaces *Flag
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

func NewMisconfFlagGroup() *MisconfFlagGroup {
	return &MisconfFlagGroup{
		FilePatterns:       &FilePatternsFlag,
		IncludeNonFailures: &IncludeNonFailuresFlag,
		SkipPolicyUpdate:   &SkipPolicyUpdateFlag,
		Trace:              &TraceFlag,
		PolicyPaths:        &ConfigPolicyFlag,
		DataPaths:          &ConfigDataFlag,
		PolicyNamespaces:   &PolicyNamespaceFlag,
	}
}

func (f *MisconfFlagGroup) Name() string {
	return "Misconfiguration"
}

func (f *MisconfFlagGroup) Flags() []*Flag {
	return []*Flag{f.FilePatterns, f.IncludeNonFailures, f.SkipPolicyUpdate, f.Trace, f.PolicyPaths, f.DataPaths, f.PolicyNamespaces}
}

func (f *MisconfFlagGroup) ToOptions() (MisconfOptions, error) {
	skipPolicyUpdateFlag := getBool(f.SkipPolicyUpdate)
	if skipPolicyUpdateFlag {
		log.Logger.Warn("'--skip-policy-update' is no longer necessary as the built-in policies are embedded into the binary")
	}
	return MisconfOptions{
		FilePatterns:       getStringSlice(f.FilePatterns),
		IncludeNonFailures: getBool(f.IncludeNonFailures),
		Trace:              getBool(f.Trace),

		PolicyPaths:      getStringSlice(f.PolicyPaths),
		DataPaths:        getStringSlice(f.DataPaths),
		PolicyNamespaces: getStringSlice(f.PolicyNamespaces),
	}, nil
}
