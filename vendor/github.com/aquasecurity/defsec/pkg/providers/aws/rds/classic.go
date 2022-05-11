package rds

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Classic struct {
	types.Metadata
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	types.Metadata
}
