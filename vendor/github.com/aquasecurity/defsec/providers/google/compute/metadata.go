package compute

import "github.com/aquasecurity/defsec/parsers/types"

type ProjectMetadata struct {
	types.Metadata
	EnableOSLogin types.BoolValue
}
