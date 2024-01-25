package iam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type IAM struct {
	Organizations                 []Organization
	WorkloadIdentityPoolProviders []WorkloadIdentityPoolProvider
}

type Organization struct {
	Metadata defsecTypes.MisconfigMetadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	Metadata defsecTypes.MisconfigMetadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Project struct {
	Metadata          defsecTypes.MisconfigMetadata
	AutoCreateNetwork defsecTypes.BoolValue
	Members           []Member
	Bindings          []Binding
}

type Binding struct {
	Metadata                      defsecTypes.MisconfigMetadata
	Members                       []defsecTypes.StringValue
	Role                          defsecTypes.StringValue
	IncludesDefaultServiceAccount defsecTypes.BoolValue
}

type Member struct {
	Metadata              defsecTypes.MisconfigMetadata
	Member                defsecTypes.StringValue
	Role                  defsecTypes.StringValue
	DefaultServiceAccount defsecTypes.BoolValue
}

type WorkloadIdentityPoolProvider struct {
	Metadata                       defsecTypes.MisconfigMetadata
	WorkloadIdentityPoolId         defsecTypes.StringValue
	WorkloadIdentityPoolProviderId defsecTypes.StringValue
	AttributeCondition             defsecTypes.StringValue
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
