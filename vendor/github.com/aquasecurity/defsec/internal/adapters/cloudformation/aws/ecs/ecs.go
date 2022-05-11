package ecs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ecs.ECS) {

	result.Clusters = getClusters(cfFile)
	result.TaskDefinitions = getTaskDefinitions(cfFile)
	return result

}
