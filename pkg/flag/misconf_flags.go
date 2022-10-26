package flag

// e.g. config yaml:
//
//	misconfiguration:
//	  trace: true
//	  config-policy: "custom-policy/policy"
//	  policy-namespaces: "user"
var (
	IncludeNonFailuresFlag = Flag{
		Name:       "include-non-failures",
		ConfigName: "misconfiguration.include-non-failures",
		Value:      false,
		Usage:      "include successes and exceptions, available with '--security-checks config'",
	}
	HelmValuesFileFlag = Flag{
		Name:       "helm-values",
		ConfigName: "misconfiguration.helm.values",
		Value:      []string{},
		Usage:      "specify paths to override the Helm values.yaml files",
	}
	HelmSetFlag = Flag{
		Name:       "helm-set",
		ConfigName: "misconfiguration.helm.set",
		Value:      []string{},
		Usage:      "specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	HelmSetFileFlag = Flag{
		Name:       "helm-set-file",
		ConfigName: "misconfiguration.helm.set-file",
		Value:      []string{},
		Usage:      "specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)",
	}
	HelmSetStringFlag = Flag{
		Name:       "helm-set-string",
		ConfigName: "misconfiguration.helm.set-string",
		Value:      []string{},
		Usage:      "specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)",
	}
	TfVarsFlag = Flag{
		Name:       "tf-vars",
		ConfigName: "misconfiguration.terraform.vars",
		Value:      []string{},
		Usage:      "specify paths to override the Terraform tfvars files",
	}
)

// MisconfFlagGroup composes common printer flag structs used for commands providing misconfinguration scanning.
type MisconfFlagGroup struct {
	IncludeNonFailures *Flag

	// Values Files
	HelmValues       *Flag
	HelmValueFiles   *Flag
	HelmFileValues   *Flag
	HelmStringValues *Flag
	TerraformTFVars  *Flag
}

type MisconfOptions struct {
	IncludeNonFailures bool

	// Values Files
	HelmValues       []string
	HelmValueFiles   []string
	HelmFileValues   []string
	HelmStringValues []string
	TerraformTFVars  []string
}

func NewMisconfFlagGroup() *MisconfFlagGroup {
	return &MisconfFlagGroup{
		IncludeNonFailures: &IncludeNonFailuresFlag,
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
		f.IncludeNonFailures,
		f.HelmValues,
		f.HelmValueFiles,
		f.HelmFileValues,
		f.HelmStringValues,
		f.TerraformTFVars,
	}
}

func (f *MisconfFlagGroup) ToOptions() (MisconfOptions, error) {
	return MisconfOptions{
		IncludeNonFailures: getBool(f.IncludeNonFailures),
		HelmValues:         getStringSlice(f.HelmValues),
		HelmValueFiles:     getStringSlice(f.HelmValueFiles),
		HelmFileValues:     getStringSlice(f.HelmFileValues),
		HelmStringValues:   getStringSlice(f.HelmStringValues),
		TerraformTFVars:    getStringSlice(f.TerraformTFVars),
	}, nil
}
