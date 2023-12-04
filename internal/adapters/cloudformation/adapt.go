package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/trivy/internal/adapters/cloudformation/aws"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt CloudFormation
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
