package types

import dio "github.com/aquasecurity/go-dep-parser/pkg/io"

type Library struct {
	ID                 string `json:",omitempty"`
	Name               string
	Version            string
	Indirect           bool          `json:",omitempty"`
	License            string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:",omitempty"`
	Locations          []Location    `json:",omitempty"`
}

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
