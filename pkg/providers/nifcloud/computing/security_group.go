package computing

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SecurityGroup struct {
	Metadata     defsecTypes.MisconfigMetadata
	Description  defsecTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata    defsecTypes.MisconfigMetadata
	Description defsecTypes.StringValue
	CIDR        defsecTypes.StringValue
}
