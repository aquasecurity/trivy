package computing

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SecurityGroup struct {
	Metadata     iacTypes.Metadata
	Description  iacTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDR        iacTypes.StringValue
}
