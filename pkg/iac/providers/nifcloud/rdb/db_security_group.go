package rdb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DBSecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}
