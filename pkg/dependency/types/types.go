package types

import (
	"encoding/json"

	"golang.org/x/xerrors"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Library struct {
	ID                 string `json:",omitempty"`
	Name               string
	Version            string
	Dev                bool          `json:",omitempty"`
	Relationship       Relationship  `json:",omitempty"`
	License            string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:",omitempty"`
	Locations          Locations     `json:",omitempty"`
	FilePath           string        `json:",omitempty"` // Required to show nested jars
}

type Libraries []Library

func (libs Libraries) Len() int { return len(libs) }
func (libs Libraries) Less(i, j int) bool {
	switch {
	case libs[i].Relationship != libs[j].Relationship:
		if libs[i].Relationship == RelationshipUnknown {
			return false
		} else if libs[j].Relationship == RelationshipUnknown {
			return true
		}
		return libs[i].Relationship < libs[j].Relationship
	case libs[i].ID != libs[j].ID: // ID could be empty
		return libs[i].ID < libs[j].ID
	case libs[i].Name != libs[j].Name: // Name could be the same
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

type Locations []Location

func (locs Locations) Len() int { return len(locs) }
func (locs Locations) Less(i, j int) bool {
	return locs[i].StartLine < locs[j].StartLine
}
func (locs Locations) Swap(i, j int) { locs[i], locs[j] = locs[j], locs[i] }

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
	Parse(r xio.ReadSeekerAt) ([]Library, []Dependency, error)
}

type RefType string

const (
	RefVCS   RefType = "vcs"
	RefOther RefType = "other"
)

type Relationship int

const (
	RelationshipUnknown Relationship = iota
	RelationshipRoot
	RelationshipDirect
	RelationshipIndirect
)

var relationshipNames = [...]string{
	"unknown",
	"root",
	"direct",
	"indirect",
}

func (r Relationship) String() string {
	if r <= RelationshipUnknown || int(r) >= len(relationshipNames) {
		return "unknown"
	}
	return relationshipNames[r]
}

func (r Relationship) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *Relationship) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range relationshipNames {
		if s == name {
			*r = Relationship(i)
			return nil
		}
	}
	return xerrors.Errorf("invalid relationship (%s)", s)
}
