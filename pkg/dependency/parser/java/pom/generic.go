package pom

import (
	"net/url"

	"github.com/aquasecurity/trivy/pkg/log"
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
}

// createURLForRepository creates a URL object for the given repository.
// If credentials are found in the provided servers list, they are embedded in the URL.
func createURLForRepository(repository repository, servers []Server) *url.URL {
	logger := log.WithPrefix("pom")
	repoURL, err := url.Parse(repository.URL)
	if err != nil {
		logger.Warn("Unable to parse remote repository url", log.Err(err))
		return nil
	}

	// Get the credentials from settings.xml based on matching server id
	// with the repository id from pom.xml and use it for accessing the repository url
	for _, server := range servers {

		if repository.ID == server.ID && server.Username != "" && server.Password != "" {
			logger.Debug("Setting credentials for repository",
				log.String("id", repository.ID), log.String("url", repository.URL))
			repoURL.User = url.UserPassword(server.Username, server.Password)
			break
		}
	}
	return repoURL
}

type Identifiable interface {
	GetID() string
}

// containsByID is a generic helper to determine if an item with the given ID exists in the slice.
func containsByID[T Identifiable](items []T, id string) bool {
	_, ok := lo.Find(items, func(item T) bool { return item.GetID() == id })
	return ok
}
