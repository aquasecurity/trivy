package types

import (
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

type Library struct {
	ID                 string `json:",omitempty"`
	Name               string
	Version            string
	Indirect           bool          `json:",omitempty"`
	License            string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:",omitempty"`
	Locations          []Location    `json:",omitempty"`
}

type Libraries []Library

func (libs Libraries) Len() int { return len(libs) }
func (libs Libraries) Less(i, j int) bool {
	if libs[i].ID != libs[j].ID { // ID could be empty
		return libs[i].ID < libs[j].ID
	} else if libs[i].Name != libs[j].Name { // Name could be the same
		return libs[i].Name < libs[j].Name
	}
	return libs[i].Version < libs[j].Version
}
func (libs Libraries) Swap(i, j int) { libs[i], libs[j] = libs[j], libs[i] }

// Location in lock file
type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

type ExternalRef struct {
	Type RefType
	URL  string
}

type Dependency struct {
	ID        string
	DependsOn []string
}

type Dependencies []Dependency

func (deps Dependencies) Len() int { return len(deps) }
func (deps Dependencies) Less(i, j int) bool {
	return deps[i].ID < deps[j].ID
}
func (deps Dependencies) Swap(i, j int) { deps[i], deps[j] = deps[j], deps[i] }

type Parser interface {
	// Parse parses the dependency file
	Parse(r dio.ReadSeekerAt) ([]Library, []Dependency, error)
}

type RefType string

const (
	RefWebsite      RefType = "website"
	RefLicense      RefType = "license"
	RefVCS          RefType = "vcs"
	RefIssueTracker RefType = "issue-tracker"
	RefOther        RefType = "other"
)
