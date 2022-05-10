package ecr

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/ecr"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ecr.ECR) {

	result.Repositories = getRepositories(cfFile)
	return result

}
