package pom

import (
	"encoding/xml"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/lo/mutable"
	"golang.org/x/net/html/charset"
)

type Server struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}
type Mirror struct {
	ID       string `xml:"id"`
	Name     string `xml:"name"`
	URL      string `xml:"url"`
	MirrorOf string `xml:"mirrorOf"`
}

type Profile struct {
	ID              string          `xml:"id"`
	Repositories    []pomRepository `xml:"repositories>repository"`
	ActiveByDefault bool            `xml:"activation>activeByDefault"`
}

type settings struct {
	LocalRepository string    `xml:"localRepository"`
	Mirrors         []Mirror  `xml:"mirrors>mirror"`
	Servers         []Server  `xml:"servers>server"`
	Profiles        []Profile `xml:"profiles>profile"`
	ActiveProfiles  []string  `xml:"activeProfiles>activeProfile"`
}

func (s settings) effectiveRepositories() []repository {
	var pomRepos []pomRepository
	for _, profile := range s.Profiles {
		if slices.Contains(s.ActiveProfiles, profile.ID) || profile.ActiveByDefault {
			pomRepos = append(pomRepos, profile.Repositories...)
		}
	}
	pomRepos = lo.UniqBy(pomRepos, func(r pomRepository) string {
		return r.ID
	})

	// mvn takes repositories from settings in reverse order
	// cf. https://github.com/aquasecurity/trivy/issues/7807#issuecomment-2541485152
	mutable.Reverse(pomRepos)

	return resolvePomRepos(s.Servers, pomRepos)
}

func readSettings() settings {
	s := settings{}

	userSettingsPath := filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
	userSettings, err := openSettings(userSettingsPath)
	if err == nil {
		s = userSettings
	}

	// Some package managers use this path by default
	mavenHome := "/usr/share/maven"
	if mHome := os.Getenv("MAVEN_HOME"); mHome != "" {
		mavenHome = mHome
	}
	globalSettingsPath := filepath.Join(mavenHome, "conf", "settings.xml")
	globalSettings, err := openSettings(globalSettingsPath)
	if err == nil {
		// We need to merge global and user settings. User settings being dominant.
		// https://maven.apache.org/settings.html#quick-overview
		if s.LocalRepository == "" {
			s.LocalRepository = globalSettings.LocalRepository
		}
		//merge Mirrors
		s.Mirrors = append(s.Mirrors, globalSettings.Mirrors...)

		// Maven servers
		s.Servers = lo.UniqBy(append(s.Servers, globalSettings.Servers...), func(server Server) string {
			return server.ID
		})

		// Merge profiles
		s.Profiles = lo.UniqBy(append(s.Profiles, globalSettings.Profiles...), func(p Profile) string {
			return p.ID
		})
		// Merge active profiles
		s.ActiveProfiles = lo.Uniq(append(s.ActiveProfiles, globalSettings.ActiveProfiles...))
	}

	return s
}

func openSettings(filePath string) (settings, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return settings{}, err
	}
	defer f.Close()

	s := settings{}
	decoder := xml.NewDecoder(f)
	decoder.CharsetReader = charset.NewReaderLabel
	if err = decoder.Decode(&s); err != nil {
		return settings{}, err
	}

	expandAllEnvPlaceholders(&s)

	return s, nil
}

func expandAllEnvPlaceholders(s *settings) {
	s.LocalRepository = evaluateVariable(s.LocalRepository, nil, nil)
	for i, mirror := range s.Mirrors {
		s.Mirrors[i].ID = evaluateVariable(mirror.ID, nil, nil)
		s.Mirrors[i].Name = evaluateVariable(mirror.Name, nil, nil)
		s.Mirrors[i].URL = evaluateVariable(mirror.URL, nil, nil)
		s.Mirrors[i].MirrorOf = evaluateVariable(mirror.MirrorOf, nil, nil)
	}
	for i, server := range s.Servers {
		s.Servers[i].ID = evaluateVariable(server.ID, nil, nil)
		s.Servers[i].Username = evaluateVariable(server.Username, nil, nil)
		s.Servers[i].Password = evaluateVariable(server.Password, nil, nil)
	}

	for i, profile := range s.Profiles {
		s.Profiles[i].ID = evaluateVariable(profile.ID, nil, nil)
		for j, repo := range profile.Repositories {
			s.Profiles[i].Repositories[j].ID = evaluateVariable(repo.ID, nil, nil)
			s.Profiles[i].Repositories[j].Name = evaluateVariable(repo.Name, nil, nil)
			s.Profiles[i].Repositories[j].URL = evaluateVariable(repo.URL, nil, nil)
		}
	}
	for i, activeProfile := range s.ActiveProfiles {
		s.ActiveProfiles[i] = evaluateVariable(activeProfile, nil, nil)
	}
}
func (s settings) ResolveMirror(repoID, repoURL string) string {
	for _, mirror := range s.Mirrors {
		if s.isMirrorMatch(mirror, repoID, repoURL) {
			return mirror.URL
		}
	}
	return repoURL
}
func (s settings) isMirrorMatch(mirror Mirror, repoID, repoURL string) bool {
	patterns := strings.Split(mirror.MirrorOf, ",")
	matches := false

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if strings.HasPrefix(pattern, "!") {
			if pattern[1:] == repoID {
				return false
			}
			continue
		}
		if pattern == "*" {
			matches = true
			continue
		}
		if pattern == "external:*" {
			if s.isExternalRepo(repoURL) {
				matches = true
			}
			continue
		}
		if pattern == repoID {
			matches = true
		}
	}
	return matches
}
func (s settings) isExternalRepo(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	if u.Scheme == "file" {
		return false
	}
	hostname := u.Hostname()
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return false
	}
	return true
}
