package codebuild

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a CodeBuild instance
func Adapt(cfFile parser.FileContext) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: getProjects(cfFile),
	}
}
