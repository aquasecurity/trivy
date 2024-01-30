package rdb

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/rdb"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func adaptDBSecurityGroups(modules terraform.Modules) []rdb.DBSecurityGroup {
	var dbSecurityGroups []rdb.DBSecurityGroup

	for _, resource := range modules.GetResourcesByType("nifcloud_db_security_group") {
		dbSecurityGroups = append(dbSecurityGroups, adaptDBSecurityGroup(resource))
	}
	return dbSecurityGroups
}

func adaptDBSecurityGroup(resource *terraform.Block) rdb.DBSecurityGroup {
	var cidrs []defsecTypes.StringValue

	for _, rule := range resource.GetBlocks("rule") {
		cidrs = append(cidrs, rule.GetAttribute("cidr_ip").AsStringValueOrDefault("", resource))
	}

	return rdb.DBSecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: resource.GetAttribute("description").AsStringValueOrDefault("", resource),
		CIDRs:       cidrs,
	}
}
