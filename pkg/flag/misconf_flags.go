package flag

import (
	"fmt"

	"github.com/samber/lo"

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
	// Deprecated
	ResetChecksBundleFlag = Flag[bool]{
		Name:       "reset-checks-bundle",
		ConfigName: "misconfiguration.reset-checks-bundle",
		Usage:      "remove checks bundle",
		Removed:    `Use "trivy clean --checks-bundle" instead`,
		Aliases: []Alias{
			{
				Name:       "reset-policy-bundle",
				ConfigName: "misconfiguration.reset-policy-bundle",
				Deprecated: true,
			},
		},
	}
	IncludeNonFailuresFlag = Flag[bool]{
		Name:       "include-non-failures",
		ConfigName: "misconfiguration.include-non-failures",
		Usage:      "include successes, available with '--scanners misconfig'",
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
	HelmAPIVersionsFlag = Flag[[]string]{
		Name:       "helm-api-versions",
		ConfigName: "misconfiguration.helm.api-versions",
		Usage:      "Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command. (can specify multiple or separate values with commas: policy/v1/PodDisruptionBudget,apps/v1/Deployment)",
	}
	HelmKubeVersionFlag = Flag[string]{
		Name:       "helm-kube-version",
		ConfigName: "misconfiguration.helm.kube-version",
		Usage:      "Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.",
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
	ChecksBundleRepositoryFlag = Flag[string]{
		Name:       "checks-bundle-repository",
		ConfigName: "misconfiguration.checks-bundle-repository",
		Default:    fmt.Sprintf("%s:%d", policy.BundleRepository, policy.BundleVersion),
		Usage:      "OCI registry URL to retrieve checks bundle from",
		Aliases: []Alias{
			{
				Name:       "policy-bundle-repository",
				ConfigName: "misconfiguration.policy-bundle-repository",
				Deprecated: true,
			},
		},
	}
	MisconfigScannersFlag = Flag[[]string]{
		Name:       "misconfig-scanners",
		ConfigName: "misconfiguration.scanners",
		Default: xstrings.ToStringSlice(
			lo.Without(analyzer.TypeConfigFiles, analyzer.TypeYAML, analyzer.TypeJSON),
		),
		Usage: "comma-separated list of misconfig scanners to use for misconfiguration scanning",
	}
	ConfigFileSchemasFlag = Flag[[]string]{
		Name:       "config-file-schemas",
		ConfigName: "misconfiguration.config-file-schemas",
		Usage:      "specify paths to JSON configuration file schemas to determine that a file matches some configuration and pass the schema to Rego checks for type checking",
	}
)

// MisconfFlagGroup composes common printer flag structs used for commands providing misconfiguration scanning.
type MisconfFlagGroup struct {
	IncludeNonFailures     *Flag[bool]
	ResetChecksBundle      *Flag[bool]
	ChecksBundleRepository *Flag[string]

	// Values Files
	HelmValues                 *Flag[[]string]
	HelmValueFiles             *Flag[[]string]
	HelmFileValues             *Flag[[]string]
	HelmStringValues           *Flag[[]string]
	HelmAPIVersions            *Flag[[]string]
	HelmKubeVersion            *Flag[string]
	TerraformTFVars            *Flag[[]string]
	CloudformationParamVars    *Flag[[]string]
	TerraformExcludeDownloaded *Flag[bool]
	MisconfigScanners          *Flag[[]string]
	ConfigFileSchemas          *Flag[[]string]
}

type MisconfOptions struct {
	IncludeNonFailures     bool
	ResetChecksBundle      bool
	ChecksBundleRepository string

	// Values Files
	HelmValues              []string
	HelmValueFiles          []string
	HelmFileValues          []string
	HelmStringValues        []string
	HelmAPIVersions         []string
	HelmKubeVersion         string
	TerraformTFVars         []string
	CloudFormationParamVars []string
	TfExcludeDownloaded     bool
	MisconfigScanners       []analyzer.Type
	ConfigFileSchemas       []string
}

func NewMisconfFlagGroup() *MisconfFlagGroup {
	return &MisconfFlagGroup{
		IncludeNonFailures:     IncludeNonFailuresFlag.Clone(),
		ResetChecksBundle:      ResetChecksBundleFlag.Clone(),
		ChecksBundleRepository: ChecksBundleRepositoryFlag.Clone(),

		HelmValues:                 HelmSetFlag.Clone(),
		HelmFileValues:             HelmSetFileFlag.Clone(),
		HelmStringValues:           HelmSetStringFlag.Clone(),
		HelmValueFiles:             HelmValuesFileFlag.Clone(),
		HelmAPIVersions:            HelmAPIVersionsFlag.Clone(),
		HelmKubeVersion:            HelmKubeVersionFlag.Clone(),
		TerraformTFVars:            TfVarsFlag.Clone(),
		CloudformationParamVars:    CfParamsFlag.Clone(),
		TerraformExcludeDownloaded: TerraformExcludeDownloaded.Clone(),
		MisconfigScanners:          MisconfigScannersFlag.Clone(),
		ConfigFileSchemas:          ConfigFileSchemasFlag.Clone(),
	}
}

func (f *MisconfFlagGroup) Name() string {
	return "Misconfiguration"
}

func (f *MisconfFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.IncludeNonFailures,
		f.ResetChecksBundle,
		f.ChecksBundleRepository,
		f.HelmValues,
		f.HelmValueFiles,
		f.HelmFileValues,
		f.HelmStringValues,
		f.HelmAPIVersions,
		f.HelmKubeVersion,
		f.TerraformTFVars,
		f.TerraformExcludeDownloaded,
		f.CloudformationParamVars,
		f.MisconfigScanners,
		f.ConfigFileSchemas,
	}
}

func (f *MisconfFlagGroup) ToOptions() (MisconfOptions, error) {
	if err := parseFlags(f); err != nil {
		return MisconfOptions{}, err
	}

	return MisconfOptions{
		IncludeNonFailures:      f.IncludeNonFailures.Value(),
		ResetChecksBundle:       f.ResetChecksBundle.Value(),
		ChecksBundleRepository:  f.ChecksBundleRepository.Value(),
		HelmValues:              f.HelmValues.Value(),
		HelmValueFiles:          f.HelmValueFiles.Value(),
		HelmFileValues:          f.HelmFileValues.Value(),
		HelmStringValues:        f.HelmStringValues.Value(),
		HelmAPIVersions:         f.HelmAPIVersions.Value(),
		HelmKubeVersion:         f.HelmKubeVersion.Value(),
		TerraformTFVars:         f.TerraformTFVars.Value(),
		CloudFormationParamVars: f.CloudformationParamVars.Value(),
		TfExcludeDownloaded:     f.TerraformExcludeDownloaded.Value(),
		MisconfigScanners:       xstrings.ToTSlice[analyzer.Type](f.MisconfigScanners.Value()),
		ConfigFileSchemas:       f.ConfigFileSchemas.Value(),
	}, nil
}
