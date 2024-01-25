package elasticache

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) elasticache.ElastiCache {
	return elasticache.ElastiCache{
		Clusters:          getClusterGroups(cfFile),
		ReplicationGroups: getReplicationGroups(cfFile),
		SecurityGroups:    getSecurityGroups(cfFile),
	}
}
