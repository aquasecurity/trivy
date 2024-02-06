package flag

// e.g. config yaml:
//
//	rego:
//	  trace: true
//	  config-policy: "custom-policy/policy"
//	  policy-namespaces: "user"
var (
	SkipPolicyUpdateFlag = Flag[bool]{
		Name:       "skip-policy-update",
		ConfigName: "rego.skip-policy-update",
		Usage:      "skip fetching rego policy updates",
	}
	TraceFlag = Flag[bool]{
		Name:       "trace",
		ConfigName: "rego.trace",
		Usage:      "enable more verbose trace output for custom queries",
	}
	ConfigPolicyFlag = Flag[[]string]{
		Name:       "config-policy",
		ConfigName: "rego.policy",
		Usage:      "specify the paths to the Rego policy files or to the directories containing them, applying config files",
		Aliases: []Alias{
			{Name: "policy"},
		},
	}
	ConfigDataFlag = Flag[[]string]{
		Name:       "config-data",
		ConfigName: "rego.data",
		Usage:      "specify paths from which data for the Rego policies will be recursively loaded",
		Aliases: []Alias{
			{Name: "data"},
		},
	}
	PolicyNamespaceFlag = Flag[[]string]{
		Name:       "policy-namespaces",
		ConfigName: "rego.namespaces",
		Usage:      "Rego namespaces",
		Aliases: []Alias{
			{Name: "namespaces"},
		},
	}
)

// RegoFlagGroup composes common printer flag structs used for commands providing misconfinguration scanning.
type RegoFlagGroup struct {
	SkipPolicyUpdate *Flag[bool]
	Trace            *Flag[bool]
	PolicyPaths      *Flag[[]string]
	DataPaths        *Flag[[]string]
	PolicyNamespaces *Flag[[]string]
}

type RegoOptions struct {
	SkipPolicyUpdate bool
	Trace            bool
	PolicyPaths      []string
	DataPaths        []string
	PolicyNamespaces []string
}

func NewRegoFlagGroup() *RegoFlagGroup {
	return &RegoFlagGroup{
		SkipPolicyUpdate: SkipPolicyUpdateFlag.Clone(),
		Trace:            TraceFlag.Clone(),
		PolicyPaths:      ConfigPolicyFlag.Clone(),
		DataPaths:        ConfigDataFlag.Clone(),
		PolicyNamespaces: PolicyNamespaceFlag.Clone(),
	}
}

func (f *RegoFlagGroup) Name() string {
	return "Rego"
}

func (f *RegoFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.SkipPolicyUpdate,
		f.Trace,
		f.PolicyPaths,
		f.DataPaths,
		f.PolicyNamespaces,
	}
}

func (f *RegoFlagGroup) ToOptions() (RegoOptions, error) {
	if err := parseFlags(f); err != nil {
		return RegoOptions{}, err
	}

	return RegoOptions{
		SkipPolicyUpdate: f.SkipPolicyUpdate.Value(),
		Trace:            f.Trace.Value(),
		PolicyPaths:      f.PolicyPaths.Value(),
		DataPaths:        f.DataPaths.Value(),
		PolicyNamespaces: f.PolicyNamespaces.Value(),
	}, nil
}
