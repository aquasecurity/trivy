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
		Usage:      "specify config file patterns, available with '--security-checks config'",
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
	HelmValuesFileFlag = Flag{
		Name:       "helm-values",
		ConfigName: "misconfiguration.helm-values",
		Value:      []string{},
		Usage:      "specify paths to override the Helm values.yaml files",
	}
	HelmSetFlag = Flag{
		Name:       "helm-set",
		ConfigName: "misconfiguration.helm-set",
		Value:      []string{},
		Usage:      "specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	HelmSetFileFlag = Flag{
		Name:       "helm-set-file",
		ConfigName: "misconfiguration.helm-set-file",
		Value:      []string{},
		Usage:      "specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)",
	}
	HelmSetStringFlag = Flag{
		Name:       "helm-set-string",
		ConfigName: "misconfiguration.helm-set-string",
		Value:      []string{},
		Usage:      "specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	TfVarsFlag = Flag{
		Name:       "tf-vars",
		ConfigName: "misconfiguration.tf-vars",
		Value:      []string{},
		Usage:      "specify paths to override the Terraform tfvars files",
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

	// Values Files
	HelmValues       *Flag
	HelmValueFiles   *Flag
	HelmFileValues   *Flag
	HelmStringValues *Flag
	TerraformTFVars  *Flag
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

	// Values Files
	HelmValues       []string
	HelmValueFiles   []string
	HelmFileValues   []string
	HelmStringValues []string
	TerraformTFVars  []string
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
		HelmValues:         &HelmSetFlag,
		HelmFileValues:     &HelmSetFileFlag,
		HelmStringValues:   &HelmSetStringFlag,
		HelmValueFiles:     &HelmValuesFileFlag,
		TerraformTFVars:    &TfVarsFlag,
	}
}

func (f *MisconfFlagGroup) Name() string {
	return "Misconfiguration"
}

func (f *MisconfFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.FilePatterns,
		f.IncludeNonFailures,
		f.SkipPolicyUpdate,
		f.Trace,
		f.PolicyPaths,
		f.DataPaths,
		f.PolicyNamespaces,
		f.HelmValues,
		f.HelmValueFiles,
		f.HelmFileValues,
		f.HelmStringValues,
		f.TerraformTFVars,
	}
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

		HelmValues:       getStringSlice(f.HelmValues),
		HelmValueFiles:   getStringSlice(f.HelmValueFiles),
		HelmFileValues:   getStringSlice(f.HelmFileValues),
		HelmStringValues: getStringSlice(f.HelmStringValues),
		TerraformTFVars:  getStringSlice(f.TerraformTFVars),
	}, nil
}
