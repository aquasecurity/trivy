package nas

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type NASSecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}
