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
	ResetPolicyBundleFlag = Flag{
		Name:       "reset-policy-bundle",
		ConfigName: "misconfiguration.reset-policy-bundle",
		Default:    false,
		Usage:      "remove policy bundle",
	}
	IncludeNonFailuresFlag = Flag{
		Name:       "include-non-failures",
		ConfigName: "misconfiguration.include-non-failures",
		Default:    false,
		Usage:      "include successes and exceptions, available with '--scanners misconfig'",
	}
	HelmValuesFileFlag = Flag{
		Name:       "helm-values",
		ConfigName: "misconfiguration.helm.values",
		Default:    []string{},
		Usage:      "specify paths to override the Helm values.yaml files",
	}
	HelmSetFlag = Flag{
		Name:       "helm-set",
		ConfigName: "misconfiguration.helm.set",
		Default:    []string{},
		Usage:      "specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	HelmSetFileFlag = Flag{
		Name:       "helm-set-file",
		ConfigName: "misconfiguration.helm.set-file",
		Default:    []string{},
		Usage:      "specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)",
	}
	HelmSetStringFlag = Flag{
		Name:       "helm-set-string",
		ConfigName: "misconfiguration.helm.set-string",
		Default:    []string{},
		Usage:      "specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	TfVarsFlag = Flag{
		Name:       "tf-vars",
		ConfigName: "misconfiguration.terraform.vars",
		Default:    []string{},
		Usage:      "specify paths to override the Terraform tfvars files",
	}
	CfParamsFlag = Flag{
		Name:       "cf-params",
		ConfigName: "misconfiguration.cloudformation.params",
		Default:    []string{},
		Usage:      "specify paths to override the CloudFormation parameters files",
	}
	TerraformExcludeDownloaded = Flag{
		Name:       "tf-exclude-downloaded-modules",
		ConfigName: "misconfiguration.terraform.exclude-downloaded-modules",
		Default:    false,
		Usage:      "exclude misconfigurations for downloaded terraform modules",
	}
	PolicyBundleRepositoryFlag = Flag{
		Name:       "policy-bundle-repository",
		ConfigName: "misconfiguration.policy-bundle-repository",
		Default:    fmt.Sprintf("%s:%d", policy.BundleRepository, policy.BundleVersion),
		Usage:      "OCI registry URL to retrieve policy bundle from",
	}
	MisconfigScannersFlag = Flag{
		Name:       "misconfig-scanners",
		ConfigName: "misconfiguration.scanners",
		Default:    xstrings.ToStringSlice(analyzer.TypeConfigFiles),
		Usage:      "comma-separated list of misconfig scanners to use for misconfiguration scanning",
	}
)

// MisconfFlagGroup composes common printer flag structs used for commands providing misconfiguration scanning.
type MisconfFlagGroup struct {
	IncludeNonFailures     *Flag
	ResetPolicyBundle      *Flag
	PolicyBundleRepository *Flag

	// Values Files
	HelmValues                 *Flag
	HelmValueFiles             *Flag
	HelmFileValues             *Flag
	HelmStringValues           *Flag
	TerraformTFVars            *Flag
	CloudformationParamVars    *Flag
	TerraformExcludeDownloaded *Flag
	MisconfigScanners          *Flag
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
		IncludeNonFailures:     &IncludeNonFailuresFlag,
		ResetPolicyBundle:      &ResetPolicyBundleFlag,
		PolicyBundleRepository: &PolicyBundleRepositoryFlag,

		HelmValues:                 &HelmSetFlag,
		HelmFileValues:             &HelmSetFileFlag,
		HelmStringValues:           &HelmSetStringFlag,
		HelmValueFiles:             &HelmValuesFileFlag,
		TerraformTFVars:            &TfVarsFlag,
		CloudformationParamVars:    &CfParamsFlag,
		TerraformExcludeDownloaded: &TerraformExcludeDownloaded,
		MisconfigScanners:          &MisconfigScannersFlag,
	}
}

func (f *MisconfFlagGroup) Name() string {
	return "Misconfiguration"
}

func (f *MisconfFlagGroup) Flags() []*Flag {
	return []*Flag{
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
	return MisconfOptions{
		IncludeNonFailures:      getBool(f.IncludeNonFailures),
		ResetPolicyBundle:       getBool(f.ResetPolicyBundle),
		PolicyBundleRepository:  getString(f.PolicyBundleRepository),
		HelmValues:              getStringSlice(f.HelmValues),
		HelmValueFiles:          getStringSlice(f.HelmValueFiles),
		HelmFileValues:          getStringSlice(f.HelmFileValues),
		HelmStringValues:        getStringSlice(f.HelmStringValues),
		TerraformTFVars:         getStringSlice(f.TerraformTFVars),
		CloudFormationParamVars: getStringSlice(f.CloudformationParamVars),
		TfExcludeDownloaded:     getBool(f.TerraformExcludeDownloaded),
		MisconfigScanners:       getUnderlyingStringSlice[analyzer.Type](f.MisconfigScanners),
	}, nil
}
