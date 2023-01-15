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
		Value:      false,
		Usage:      "skip fetching rego policy updates",
	}
	TraceFlag = Flag{
		Name:       "trace",
		ConfigName: "rego.trace",
		Value:      false,
		Usage:      "enable more verbose trace output for custom queries",
	}
	ConfigPolicyFlag = Flag{
		Name:       "config-policy",
		ConfigName: "rego.policy",
		Value:      []string{},
		Usage:      "specify paths to the Rego policy files directory, applying config files",
	}
	ConfigDataFlag = Flag{
		Name:       "config-data",
		ConfigName: "rego.data",
		Value:      []string{},
		Usage:      "specify paths from which data for the Rego policies will be recursively loaded",
	}
	PolicyNamespaceFlag = Flag{
		Name:       "policy-namespaces",
		ConfigName: "rego.namespaces",
		Value:      []string{},
		Usage:      "Rego namespaces",
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
