package github

import "github.com/aquasecurity/defsec/parsers/types"

type GitHub struct {
	types.Metadata
	Repositories       []Repository
	EnvironmentSecrets []EnvironmentSecret
}
