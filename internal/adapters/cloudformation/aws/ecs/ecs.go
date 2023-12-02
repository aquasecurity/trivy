package ecs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts ecs resources
func Adapt(cfFile parser.FileContext) ecs.ECS {
	return ecs.ECS{
		Clusters:        getClusters(cfFile),
		TaskDefinitions: getTaskDefinitions(cfFile),
	}
}
