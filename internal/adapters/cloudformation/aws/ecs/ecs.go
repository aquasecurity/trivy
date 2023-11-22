package ecs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ecs.ECS {
	return ecs.ECS{
		Clusters:        getClusters(cfFile),
		TaskDefinitions: getTaskDefinitions(cfFile),
	}
}
