package rds

import (
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.Metadata
}
