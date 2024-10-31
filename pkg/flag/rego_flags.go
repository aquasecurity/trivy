package flag

// e.g. config yaml:
//
//	rego:
//	  trace: true
//	  config-policy: "custom-policy/policy"
//	  policy-namespaces: "user"
var (
	IncludeDeprecatedChecksFlag = Flag[bool]{
		Name:       "include-deprecated-checks",
		ConfigName: "rego.include-deprecated-checks",
		Usage:      "include deprecated checks",
	}
	SkipCheckUpdateFlag = Flag[bool]{
		Name:       "skip-check-update",
		ConfigName: "rego.skip-check-update",
		Usage:      "skip fetching rego check updates",
		Aliases: []Alias{
			{
				Name:       "skip-policy-update",
				ConfigName: "rego.skip-policy-update",
				Deprecated: true,
			},
		},
	}
	TraceFlag = Flag[bool]{
		Name:       "trace",
		ConfigName: "rego.trace",
		Usage:      "enable more verbose trace output for custom queries",
	}
	ConfigCheckFlag = Flag[[]string]{
		Name:       "config-check",
		ConfigName: "rego.check",
		Usage:      "specify the paths to the Rego check files or to the directories containing them, applying config files",
		Aliases: []Alias{
			{Name: "policy", Deprecated: true},
			{Name: "config-policy", Deprecated: true},
		},
	}
	ConfigDataFlag = Flag[[]string]{
		Name:       "config-data",
		ConfigName: "rego.data",
		Usage:      "specify paths from which data for the Rego checks will be recursively loaded",
		Aliases: []Alias{
			{Name: "data"},
		},
	}
	CheckNamespaceFlag = Flag[[]string]{
		Name:       "check-namespaces",
		ConfigName: "rego.namespaces",
		Usage:      "Rego namespaces",
		Aliases: []Alias{
			{Name: "namespaces"},
			{Name: "policy-namespaces", Deprecated: true},
		},
	}
)

// RegoFlagGroup composes common printer flag structs used for commands providing misconfinguration scanning.
type RegoFlagGroup struct {
	IncludeDeprecatedChecks *Flag[bool]
	SkipCheckUpdate         *Flag[bool]
	Trace                   *Flag[bool]
	CheckPaths              *Flag[[]string]
	DataPaths               *Flag[[]string]
	CheckNamespaces         *Flag[[]string]
}

type RegoOptions struct {
	IncludeDeprecatedChecks bool
	SkipCheckUpdate         bool
	Trace                   bool
	CheckPaths              []string
	DataPaths               []string
	CheckNamespaces         []string
}

func NewRegoFlagGroup() *RegoFlagGroup {
	return &RegoFlagGroup{
		IncludeDeprecatedChecks: IncludeDeprecatedChecksFlag.Clone(),
		SkipCheckUpdate:         SkipCheckUpdateFlag.Clone(),
		Trace:                   TraceFlag.Clone(),
		CheckPaths:              ConfigCheckFlag.Clone(),
		DataPaths:               ConfigDataFlag.Clone(),
		CheckNamespaces:         CheckNamespaceFlag.Clone(),
	}
}

func (f *RegoFlagGroup) Name() string {
	return "Rego"
}

func (f *RegoFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.IncludeDeprecatedChecks,
		f.SkipCheckUpdate,
		f.Trace,
		f.CheckPaths,
		f.DataPaths,
		f.CheckNamespaces,
	}
}

func (f *RegoFlagGroup) ToOptions() (RegoOptions, error) {
	if err := parseFlags(f); err != nil {
		return RegoOptions{}, err
	}

	return RegoOptions{
		IncludeDeprecatedChecks: f.IncludeDeprecatedChecks.Value(),
		SkipCheckUpdate:         f.SkipCheckUpdate.Value(),
		Trace:                   f.Trace.Value(),
		CheckPaths:              f.CheckPaths.Value(),
		DataPaths:               f.DataPaths.Value(),
		CheckNamespaces:         f.CheckNamespaces.Value(),
	}, nil
}
