package iam

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type IAM struct {
	Organizations                 []Organization
	WorkloadIdentityPoolProviders []WorkloadIdentityPoolProvider
}

type Organization struct {
	Metadata iacTypes.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	Metadata iacTypes.Metadata
	Folders  []Folder
	Projects []Project
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
	var projects []Project
	for _, org := range p.Organizations {
		projects = append(projects, org.Projects...)
		for _, folder := range org.Folders {
			projects = append(projects, folder.Projects...)
			for _, desc := range folder.AllFolders() {
				projects = append(projects, desc.Projects...)
			}
		}
	}
	return projects
}

func (p *IAM) AllFolders() []Folder {
	var folders []Folder
	for _, org := range p.Organizations {
		folders = append(folders, org.Folders...)
		for _, folder := range org.Folders {
			folders = append(folders, folder.AllFolders()...)
		}
	}
	return folders
}

func (f *Folder) AllFolders() []Folder {
	var folders []Folder
	for _, folder := range f.Folders {
		folders = append(folders, folder)
		folders = append(folders, folder.AllFolders()...)
	}
	return folders
}
