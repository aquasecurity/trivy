package vpc

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type VPC struct {
	DefaultVPCs    []DefaultVPC
	SecurityGroups []SecurityGroup
	NetworkACLs    []NetworkACL
}

type NetworkACL struct {
	types.Metadata
	Rules []NetworkACLRule
}

type SecurityGroup struct {
	types.Metadata
	Description  types.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	types.Metadata
	Description types.StringValue
	CIDRs       []types.StringValue
}

type DefaultVPC struct {
	types.Metadata
}

const (
	TypeIngress = "ingress"
	TypeEgress  = "egress"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

type NetworkACLRule struct {
	types.Metadata
	Type     types.StringValue
	Action   types.StringValue
	Protocol types.StringValue
	CIDRs    []types.StringValue
}
