package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type NetworkACL struct {
	Metadata      defsecTypes.MisconfigMetadata
	Rules         []NetworkACLRule
	IsDefaultRule defsecTypes.BoolValue
}

type SecurityGroup struct {
	Metadata     defsecTypes.MisconfigMetadata
	IsDefault    defsecTypes.BoolValue
	Description  defsecTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
	VPCID        defsecTypes.StringValue
}

type SecurityGroupRule struct {
	Metadata    defsecTypes.MisconfigMetadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}

type VPC struct {
	Metadata        defsecTypes.MisconfigMetadata
	ID              defsecTypes.StringValue
	IsDefault       defsecTypes.BoolValue
	SecurityGroups  []SecurityGroup
	FlowLogsEnabled defsecTypes.BoolValue
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
	Metadata defsecTypes.MisconfigMetadata
	Type     defsecTypes.StringValue
	Action   defsecTypes.StringValue
	Protocol defsecTypes.StringValue
	CIDRs    []defsecTypes.StringValue
}
