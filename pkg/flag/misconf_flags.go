package flag

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/policy"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

// e.g. config yaml:
//
//	misconfiguration:
//	  trace: true
//	  config-policy: "custom-policy/policy"
//	  policy-namespaces: "user"
var (
	ResetPolicyBundleFlag = Flag[bool]{
		Name:       "reset-policy-bundle",
		ConfigName: "misconfiguration.reset-policy-bundle",
		Usage:      "remove policy bundle",
	}
	IncludeNonFailuresFlag = Flag[bool]{
		Name:       "include-non-failures",
		ConfigName: "misconfiguration.include-non-failures",
		Usage:      "include successes and exceptions, available with '--scanners misconfig'",
	}
	HelmValuesFileFlag = Flag[[]string]{
		Name:       "helm-values",
		ConfigName: "misconfiguration.helm.values",
		Usage:      "specify paths to override the Helm values.yaml files",
	}
	HelmSetFlag = Flag[[]string]{
		Name:       "helm-set",
		ConfigName: "misconfiguration.helm.set",
		Usage:      "specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	HelmSetFileFlag = Flag[[]string]{
		Name:       "helm-set-file",
		ConfigName: "misconfiguration.helm.set-file",
		Usage:      "specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)",
	}
	HelmSetStringFlag = Flag[[]string]{
		Name:       "helm-set-string",
		ConfigName: "misconfiguration.helm.set-string",
		Usage:      "specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	TfVarsFlag = Flag[[]string]{
		Name:       "tf-vars",
		ConfigName: "misconfiguration.terraform.vars",
		Usage:      "specify paths to override the Terraform tfvars files",
	}
	CfParamsFlag = Flag[[]string]{
		Name:       "cf-params",
		ConfigName: "misconfiguration.cloudformation.params",
		Default:    []string{},
		Usage:      "specify paths to override the CloudFormation parameters files",
	}
	TerraformExcludeDownloaded = Flag[bool]{
		Name:       "tf-exclude-downloaded-modules",
		ConfigName: "misconfiguration.terraform.exclude-downloaded-modules",
		Usage:      "exclude misconfigurations for downloaded terraform modules",
	}
	PolicyBundleRepositoryFlag = Flag[string]{
		Name:       "policy-bundle-repository",
		ConfigName: "misconfiguration.policy-bundle-repository",
		Default:    fmt.Sprintf("%s:%d", policy.BundleRepository, policy.BundleVersion),
		Usage:      "OCI registry URL to retrieve policy bundle from",
	}
	MisconfigScannersFlag = Flag[[]string]{
		Name:       "misconfig-scanners",
		ConfigName: "misconfiguration.scanners",
		Default:    xstrings.ToStringSlice(analyzer.TypeConfigFiles),
		Usage:      "comma-separated list of misconfig scanners to use for misconfiguration scanning",
	}
)

// MisconfFlagGroup composes common printer flag structs used for commands providing misconfiguration scanning.
type MisconfFlagGroup struct {
	IncludeNonFailures     *Flag[bool]
	ResetPolicyBundle      *Flag[bool]
	PolicyBundleRepository *Flag[string]

	// Values Files
	HelmValues                 *Flag[[]string]
	HelmValueFiles             *Flag[[]string]
	HelmFileValues             *Flag[[]string]
	HelmStringValues           *Flag[[]string]
	TerraformTFVars            *Flag[[]string]
	CloudformationParamVars    *Flag[[]string]
	TerraformExcludeDownloaded *Flag[bool]
	MisconfigScanners          *Flag[[]string]
}

type MisconfOptions struct {
	IncludeNonFailures     bool
	ResetPolicyBundle      bool
	PolicyBundleRepository string

	// Values Files
	HelmValues              []string
	HelmValueFiles          []string
	HelmFileValues          []string
	HelmStringValues        []string
	TerraformTFVars         []string
	CloudFormationParamVars []string
	TfExcludeDownloaded     bool
	MisconfigScanners       []analyzer.Type
}

func NewMisconfFlagGroup() *MisconfFlagGroup {
	return &MisconfFlagGroup{
		IncludeNonFailures:     IncludeNonFailuresFlag.Clone(),
		ResetPolicyBundle:      ResetPolicyBundleFlag.Clone(),
		PolicyBundleRepository: PolicyBundleRepositoryFlag.Clone(),

		HelmValues:                 HelmSetFlag.Clone(),
		HelmFileValues:             HelmSetFileFlag.Clone(),
		HelmStringValues:           HelmSetStringFlag.Clone(),
		HelmValueFiles:             HelmValuesFileFlag.Clone(),
		TerraformTFVars:            TfVarsFlag.Clone(),
		CloudformationParamVars:    CfParamsFlag.Clone(),
		TerraformExcludeDownloaded: TerraformExcludeDownloaded.Clone(),
		MisconfigScanners:          MisconfigScannersFlag.Clone(),
	}
}

func (f *MisconfFlagGroup) Name() string {
	return "Misconfiguration"
}

func (f *MisconfFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.IncludeNonFailures,
		f.ResetPolicyBundle,
		f.PolicyBundleRepository,
		f.HelmValues,
		f.HelmValueFiles,
		f.HelmFileValues,
		f.HelmStringValues,
		f.TerraformTFVars,
		f.TerraformExcludeDownloaded,
		f.CloudformationParamVars,
		f.MisconfigScanners,
	}
}

func (f *MisconfFlagGroup) ToOptions() (MisconfOptions, error) {
	if err := parseFlags(f); err != nil {
		return MisconfOptions{}, err
	}

	return MisconfOptions{
		IncludeNonFailures:      f.IncludeNonFailures.Value(),
		ResetPolicyBundle:       f.ResetPolicyBundle.Value(),
		PolicyBundleRepository:  f.PolicyBundleRepository.Value(),
		HelmValues:              f.HelmValues.Value(),
		HelmValueFiles:          f.HelmValueFiles.Value(),
		HelmFileValues:          f.HelmFileValues.Value(),
		HelmStringValues:        f.HelmStringValues.Value(),
		TerraformTFVars:         f.TerraformTFVars.Value(),
		CloudFormationParamVars: f.CloudformationParamVars.Value(),
		TfExcludeDownloaded:     f.TerraformExcludeDownloaded.Value(),
		MisconfigScanners:       xstrings.ToTSlice[analyzer.Type](f.MisconfigScanners.Value()),
	}, nil
}
