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
	Metadata iacTypes.Metadata
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	Metadata iacTypes.Metadata
	Members  []Member
	Bindings []Binding
}

type Project struct {
	Metadata          iacTypes.Metadata
	AutoCreateNetwork iacTypes.BoolValue
	Members           []Member
	Bindings          []Binding
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

type WorkloadIdentityPoolProvider struct {
	Metadata                       iacTypes.Metadata
	WorkloadIdentityPoolId         iacTypes.StringValue
	WorkloadIdentityPoolProviderId iacTypes.StringValue
	AttributeCondition             iacTypes.StringValue
}

func (p *IAM) AllProjects() []Project {
	return p.Projects
}

func (p *IAM) AllFolders() []Folder {
	return p.Folders
}
