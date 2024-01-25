package ecr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ecr.ECR {
	return ecr.ECR{
		Repositories: getRepositories(cfFile),
	}
}
