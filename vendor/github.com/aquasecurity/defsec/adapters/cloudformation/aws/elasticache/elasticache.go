package elasticache

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/elasticache"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elasticache.ElastiCache) {
	result.Clusters = getClusterGroups(cfFile)
	result.ReplicationGroups = getReplicationGroups(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result
}
