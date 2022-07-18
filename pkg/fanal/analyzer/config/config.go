package config

import (
	"sort"
)

const separator = ":"

type ScannerOption struct {
	Trace                   bool
	RegoOnly                bool
	Namespaces              []string
	PolicyPaths             []string
	DataPaths               []string
	DisableEmbeddedPolicies bool
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}
