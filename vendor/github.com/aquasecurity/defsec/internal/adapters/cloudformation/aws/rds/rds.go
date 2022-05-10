package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result rds.RDS) {

	clusters, orphans := getClustersAndInstances(cfFile)

	result.Instances = orphans
	result.Clusters = clusters
	result.Classic = getClassic(cfFile)
	return result
}
