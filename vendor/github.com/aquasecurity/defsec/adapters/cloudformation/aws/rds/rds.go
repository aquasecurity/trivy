package rds

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/rds"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result rds.RDS) {

	clusters, orphans := getClustersAndInstances(cfFile)

	result.Instances = orphans
	result.Clusters = clusters
	result.Classic = getClassic(cfFile)
	return result
}
