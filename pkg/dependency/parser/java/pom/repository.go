package pom

import (
	"errors"
	"net/url"

	"github.com/aquasecurity/trivy/pkg/log"
)

var centralURL, _ = url.Parse("https://repo.maven.apache.org/maven2/")

type repository struct {
	url             url.URL
	releaseEnabled  bool
	snapshotEnabled bool
}

type repositories struct {
	settings    []repository // Repositories from settings.xml files
	defaultRepo repository   // Default repository - Maven Central for Release, empty for Snapshot
}

var mavenCentralRepo = repository{
	url:            *centralURL,
	releaseEnabled: true,
}

func resolvePomRepos(servers []Server, pomRepos []pomRepository) []repository {
	logger := log.WithPrefix("pom")
	var repos []repository
	for _, rep := range pomRepos {
		r := repository{
			// "<enabled>: true or false for whether this repository is enabled for the respective type (releases or snapshots). By default, this is true."
			// cf. https://maven.apache.org/pom.html#Repositories
			releaseEnabled:  rep.ReleasesEnabled == trueString || rep.ReleasesEnabled == "",
			snapshotEnabled: rep.SnapshotsEnabled == trueString || rep.SnapshotsEnabled == "",
		}

		// Add only enabled repositories
		if !r.releaseEnabled && !r.snapshotEnabled {
			continue
		}

		repoURL, err := url.Parse(rep.URL)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Unwrap()
			}
			logger.Debug("Unable to parse remote repository url", log.String("id", rep.ID), log.Err(err))
			continue
		}

		// Get the credentials from settings.xml based on matching server id
		// with the repository id from pom.xml and use it for accessing the repository url
		for _, server := range servers {
			if rep.ID == server.ID && server.Username != "" && server.Password != "" {
				repoURL.User = url.UserPassword(server.Username, server.Password)
				break
			}
		}

		logger.Debug("Adding repository", log.String("id", rep.ID), log.String("url", repoURL.Redacted()))
		r.url = *repoURL
		repos = append(repos, r)
	}
	return repos
}
