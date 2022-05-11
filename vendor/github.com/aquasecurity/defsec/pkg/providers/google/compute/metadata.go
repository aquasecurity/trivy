package compute

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type ProjectMetadata struct {
	types.Metadata
	EnableOSLogin types.BoolValue
}
