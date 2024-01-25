package cloudformation

import (
	"github.com/aquasecurity/trivy/internal/adapters/cloudformation/aws"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/state"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
