package iam

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type IAM struct {
	Organizations []Organization
}

type Organization struct {
	types.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	types.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Project struct {
	types.Metadata
	AutoCreateNetwork types.BoolValue
	Members           []Member
	Bindings          []Binding
}

type Binding struct {
	types.Metadata
	Members                       []types.StringValue
	Role                          types.StringValue
	IncludesDefaultServiceAccount types.BoolValue
}

type Member struct {
	types.Metadata
	Member                types.StringValue
	Role                  types.StringValue
	DefaultServiceAccount types.BoolValue
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
