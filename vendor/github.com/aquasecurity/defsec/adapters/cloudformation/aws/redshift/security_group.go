package redshift

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/redshift"
)

func getSecurityGroups(ctx parser.FileContext) (groups []redshift.SecurityGroup) {
	for _, groupResource := range ctx.GetResourcesByType("AWS::Redshift::ClusterSecurityGroup") {
		group := redshift.SecurityGroup{
			Metadata:    groupResource.Metadata(),
			Description: groupResource.GetProperty("Description").AsStringValue(),
		}
		groups = append(groups, group)
	}
	return groups
}
