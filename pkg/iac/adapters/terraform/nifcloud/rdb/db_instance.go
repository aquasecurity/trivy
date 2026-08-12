package rdb

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/rdb"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptDBInstances(modules terraform.Modules) []rdb.DBInstance {
	var dbInstances []rdb.DBInstance

	for _, resource := range modules.GetResourcesByType("nifcloud_db_instance") {
		dbInstances = append(dbInstances, adaptDBInstance(resource))
	}
	return dbInstances
}

func adaptDBInstance(resource *terraform.Block) rdb.DBInstance {
	return rdb.DBInstance{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValue(),
		Engine:                    resource.GetAttribute("engine").AsStringValue(),
		EngineVersion:             resource.GetAttribute("engine_version").AsStringValue(),
		NetworkID:                 resource.GetAttribute("network_id").AsStringValue("net-COMMON_PRIVATE"),
		PublicAccess:              resource.GetAttribute("publicly_accessible").AsBoolValue(true),
	}
}
