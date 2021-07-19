package option

import (
	"github.com/urfave/cli/v2"
)

// ConfigOption holds the options for config scanning
type ConfigOption struct {
	FilePatterns       []string
	IncludeNonFailures bool
	SkipPolicyUpdate   bool
	Trace              bool

	// Rego
	PolicyPaths      []string
	DataPaths        []string
	PolicyNamespaces []string
}

// NewConfigOption is the factory method to return config scanning options
func NewConfigOption(c *cli.Context) ConfigOption {
	return ConfigOption{
		IncludeNonFailures: c.Bool("include-non-failures"),
		SkipPolicyUpdate:   c.Bool("skip-policy-update"),
		Trace:              c.Bool("trace"),
		FilePatterns:       c.StringSlice("file-patterns"),
		PolicyPaths:        c.StringSlice("config-policy"),
		DataPaths:          c.StringSlice("config-data"),
		PolicyNamespaces:   c.StringSlice("policy-namespaces"),
	}
}
