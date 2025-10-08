package ecs

import (
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
)

// Adapt adapts an ECS instance
func Adapt(cfFile parser.FileContext) ecs.ECS {
	return ecs.ECS{
		Clusters:        getClusters(cfFile),
		TaskDefinitions: getTaskDefinitions(cfFile),
	}
}
