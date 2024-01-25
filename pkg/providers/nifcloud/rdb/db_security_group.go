package rdb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DBSecurityGroup struct {
	Metadata    defsecTypes.MisconfigMetadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}
