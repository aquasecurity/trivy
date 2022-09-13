package config

import (
	"sort"
)

type ScannerOption struct {
	Trace                   bool
	RegoOnly                bool
	Namespaces              []string
	PolicyPaths             []string
	DataPaths               []string
	DisableEmbeddedPolicies bool

	HelmValues       []string
	HelmValueFiles   []string
	HelmFileValues   []string
	HelmStringValues []string
	TerraformTFVars  []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}
