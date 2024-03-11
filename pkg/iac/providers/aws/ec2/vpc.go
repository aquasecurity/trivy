package ec2

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type NetworkACL struct {
	Metadata      iacTypes.Metadata
	Rules         []NetworkACLRule
	IsDefaultRule iacTypes.BoolValue
}

type SecurityGroup struct {
	Metadata     iacTypes.Metadata
	IsDefault    iacTypes.BoolValue
	Description  iacTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
	VPCID        iacTypes.StringValue
}

type SecurityGroupRule struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDRs       []iacTypes.StringValue
}

type VPC struct {
	Metadata        iacTypes.Metadata
	ID              iacTypes.StringValue
	IsDefault       iacTypes.BoolValue
	SecurityGroups  []SecurityGroup
	FlowLogsEnabled iacTypes.BoolValue
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
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
	Action   iacTypes.StringValue
	Protocol iacTypes.StringValue
	CIDRs    []iacTypes.StringValue
}
