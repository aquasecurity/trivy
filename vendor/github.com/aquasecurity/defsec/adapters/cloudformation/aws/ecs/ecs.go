package ecs

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/ecs"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ecs.ECS) {

	result.Clusters = getClusters(cfFile)
	result.TaskDefinitions = getTaskDefinitions(cfFile)
	return result

}
