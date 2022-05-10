package codebuild

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/codebuild"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result codebuild.CodeBuild) {

	result.Projects = getProjects(cfFile)
	return result

}
