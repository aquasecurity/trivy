package iam

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type IAM struct {
	Organizations                 []Organization
	WorkloadIdentityPoolProviders []WorkloadIdentityPoolProvider
	Projects                      []Project
	Folders                       []Folder
}

type Organization struct {
	Metadata     iacTypes.Metadata
	Members      []Member
	Bindings     []Binding
	AuditConfigs []AuditConfig
}

type Folder struct {
	Metadata     iacTypes.Metadata
	Members      []Member
	Bindings     []Binding
	AuditConfigs []AuditConfig
}

type Project struct {
	Metadata          iacTypes.Metadata
	AutoCreateNetwork iacTypes.BoolValue
	Members           []Member
	Bindings          []Binding
	AuditConfigs      []AuditConfig
}

type Binding struct {
	Metadata                      iacTypes.Metadata
	Members                       []iacTypes.StringValue
	Role                          iacTypes.StringValue
	IncludesDefaultServiceAccount iacTypes.BoolValue
}

type Member struct {
	Metadata              iacTypes.Metadata
	Member                iacTypes.StringValue
	Role                  iacTypes.StringValue
	DefaultServiceAccount iacTypes.BoolValue
}

type AuditConfig struct {
	Metadata        iacTypes.Metadata
	Service         iacTypes.StringValue
	AuditLogConfigs []AuditLogConfig
}

type AuditLogConfig struct {
	Metadata        iacTypes.Metadata
	LogType         iacTypes.StringValue
	ExemptedMembers []iacTypes.StringValue
}

type WorkloadIdentityPoolProvider struct {
	Metadata                       iacTypes.Metadata
	WorkloadIdentityPoolId         iacTypes.StringValue
	WorkloadIdentityPoolProviderId iacTypes.StringValue
	AttributeCondition             iacTypes.StringValue
}
