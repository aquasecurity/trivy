package flag

// e.g. config yaml:
//
//	rego:
//	  trace: true
//	  config-policy: "custom-policy/policy"
//	  policy-namespaces: "user"
var (
	SkipPolicyUpdateFlag = Flag{
		Name:       "skip-policy-update",
		ConfigName: "rego.skip-policy-update",
		Default:    false,
		Usage:      "skip fetching rego policy updates",
	}
	TraceFlag = Flag{
		Name:       "trace",
		ConfigName: "rego.trace",
		Default:    false,
		Usage:      "enable more verbose trace output for custom queries",
	}
	ConfigPolicyFlag = Flag{
		Name:       "config-policy",
		ConfigName: "rego.policy",
		Default:    []string{},
		Usage:      "specify the paths to the Rego policy files or to the directories containing them, applying config files",
		Aliases: []Alias{
			{Name: "policy"},
		},
	}
	ConfigDataFlag = Flag{
		Name:       "config-data",
		ConfigName: "rego.data",
		Default:    []string{},
		Usage:      "specify paths from which data for the Rego policies will be recursively loaded",
		Aliases: []Alias{
			{Name: "data"},
		},
	}
	PolicyNamespaceFlag = Flag{
		Name:       "policy-namespaces",
		ConfigName: "rego.namespaces",
		Default:    []string{},
		Usage:      "Rego namespaces",
		Aliases: []Alias{
			{Name: "namespaces"},
		},
	}
)

// RegoFlagGroup composes common printer flag structs used for commands providing misconfinguration scanning.
type RegoFlagGroup struct {
	SkipPolicyUpdate *Flag
	Trace            *Flag
	PolicyPaths      *Flag
	DataPaths        *Flag
	PolicyNamespaces *Flag
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
		SkipPolicyUpdate: &SkipPolicyUpdateFlag,
		Trace:            &TraceFlag,
		PolicyPaths:      &ConfigPolicyFlag,
		DataPaths:        &ConfigDataFlag,
		PolicyNamespaces: &PolicyNamespaceFlag,
	}
}

func (f *RegoFlagGroup) Name() string {
	return "Rego"
}

func (f *RegoFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.SkipPolicyUpdate,
		f.Trace,
		f.PolicyPaths,
		f.DataPaths,
		f.PolicyNamespaces,
	}
}

func (f *RegoFlagGroup) ToOptions() (RegoOptions, error) {
	return RegoOptions{
		SkipPolicyUpdate: getBool(f.SkipPolicyUpdate),
		Trace:            getBool(f.Trace),
		PolicyPaths:      getStringSlice(f.PolicyPaths),
		DataPaths:        getStringSlice(f.DataPaths),
		PolicyNamespaces: getStringSlice(f.PolicyNamespaces),
	}, nil
}
