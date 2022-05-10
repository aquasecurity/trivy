package elasticache

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elasticache.ElastiCache) {
	result.Clusters = getClusterGroups(cfFile)
	result.ReplicationGroups = getReplicationGroups(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result
}
