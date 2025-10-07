package codebuild

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
)

// Adapt adapts a CodeBuild instance
func Adapt(cfFile parser.FileContext) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: getProjects(cfFile),
	}
}
