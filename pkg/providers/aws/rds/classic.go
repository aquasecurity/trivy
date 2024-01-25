package rds

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.MisconfigMetadata
}
