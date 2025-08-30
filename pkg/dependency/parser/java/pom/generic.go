package pom

import (
	"github.com/samber/lo"
)

// Centralized the repository structure to be used across different parsers.
// For both pom.xml and settings.xml files.
// Because although they have their own XSD's, they share a similar structure for repositories.
// - https://maven.apache.org/xsd/settings-1.0.0.xsd
// - https://maven.apache.org/xsd/maven-4.0.0.xsd

type repositories struct {
	Repository []repository `xml:"repository"`
}

type repository struct {
	ID        string           `xml:"id"`
	Name      string           `xml:"name"`
	URL       string           `xml:"url"`
	Releases  repositoryPolicy `xml:"releases"`
	Snapshots repositoryPolicy `xml:"snapshots"`
}

type repositoryPolicy struct {
	Enabled bool `xml:"enabled"`
	// Add more fields as needed:
	// ChecksumPolicy string `xml:"checksumPolicy"`
	// UpdatePolicy   string `xml:"updatePolicy"`
}

type Identifiable interface {
	GetID() string
}

// containsByID is a generic helper to determine if an item with the given ID exists in the slice.
func containsByID[T Identifiable](items []T, id string) bool {
	_, ok := lo.Find(items, func(item T) bool { return item.GetID() == id })
	return ok
}
