package nas

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type NASSecurityGroup struct {
	Metadata    defsecTypes.MisconfigMetadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}
