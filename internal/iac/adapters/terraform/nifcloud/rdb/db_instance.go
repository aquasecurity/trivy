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
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		Engine:                    resource.GetAttribute("engine").AsStringValueOrDefault("", resource),
		EngineVersion:             resource.GetAttribute("engine_version").AsStringValueOrDefault("", resource),
		NetworkID:                 resource.GetAttribute("network_id").AsStringValueOrDefault("net-COMMON_PRIVATE", resource),
		PublicAccess:              resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(true, resource),
	}
}
