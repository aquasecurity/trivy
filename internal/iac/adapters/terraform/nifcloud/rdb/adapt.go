package rdb

import (
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/rdb"
)

func Adapt(modules terraform.Modules) rdb.RDB {
	return rdb.RDB{
		DBSecurityGroups: adaptDBSecurityGroups(modules),
		DBInstances:      adaptDBInstances(modules),
	}
}
