package ecr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ecr.ECR) {

	result.Repositories = getRepositories(cfFile)
	return result

}
