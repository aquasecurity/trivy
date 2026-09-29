package rdb

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DBSecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDRs       []iacTypes.StringValue
}
