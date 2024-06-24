package ssm

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an SSM instance
func Adapt(cfFile parser.FileContext) ssm.SSM {
	return ssm.SSM{
		Secrets: getSecrets(cfFile),
	}
}
