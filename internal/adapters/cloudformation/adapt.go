package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/trivy/internal/adapters/cloudformation/aws"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
