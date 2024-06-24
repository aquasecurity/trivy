package rdb

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/rdb"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) rdb.RDB {
	return rdb.RDB{
		DBSecurityGroups: adaptDBSecurityGroups(modules),
		DBInstances:      adaptDBInstances(modules),
	}
}
