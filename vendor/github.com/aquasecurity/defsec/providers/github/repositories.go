package github

import "github.com/aquasecurity/defsec/parsers/types"

type Repository struct {
	types.Metadata
	Public types.BoolValue
}
