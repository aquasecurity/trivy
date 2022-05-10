package elasticache

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getSecurityGroups(ctx parser.FileContext) (securityGroups []elasticache.SecurityGroup) {

	sgResources := ctx.GetResourcesByType("AWS::ElastiCache::SecurityGroup")

	for _, r := range sgResources {

		sg := elasticache.SecurityGroup{
			Metadata:    r.Metadata(),
			Description: r.GetStringProperty("Description"),
		}
		securityGroups = append(securityGroups, sg)
	}

	return securityGroups
}
