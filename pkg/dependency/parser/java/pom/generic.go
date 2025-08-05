package pom

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
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
	MirrorID  string
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

// applyMirrorSettingsForRepositories updates the repositories to match applicable mirrors from the settings.
func applyMirrorSettingsForRepositories(repositories []repository, s *settings) {
	logger := log.WithPrefix("pom")
	for i := range repositories {
		mirrorForRepo := s.findMirrorForRepository(repositories[i].ID)
		if mirrorForRepo != nil {
			logger.Debug("Using mirror for repository",
				log.String("repositoryID", repositories[i].ID), log.String("mirror.ID", mirrorForRepo.ID))
			repositories[i].applyMirrorSettings(mirrorForRepo)
		}
	}
}

// applyMirrorSettingsForRepositories updates the repository settings based on the provided mirror.
// Mirrors are always enabled for releases and for snapshots as well.
func (r *repository) applyMirrorSettings(mirror *Mirror) {
	if r == nil || mirror == nil {
		return
	}
	logger := log.WithPrefix("pom")
	if mirror.URL != "" {
		logger.Debug("Overriding url for repository (and enabling both releases and snapshots)",
			log.String("repository.URL", r.URL), log.String("mirror.URL", mirror.URL))
		r.MirrorID = mirror.ID
		r.URL = mirror.URL
		r.Releases.Enabled = true
		r.Snapshots.Enabled = true
	}
}
