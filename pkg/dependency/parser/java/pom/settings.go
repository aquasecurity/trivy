package pom

import (
	"encoding/xml"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/lo/mutable"
	"golang.org/x/net/html/charset"
)

const trueString = "true"

type Server struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}

type Profile struct {
	ID              string          `xml:"id"`
	Repositories    []pomRepository `xml:"repositories>repository"`
	ActiveByDefault bool            `xml:"activation>activeByDefault"`
}

type Proxy struct {
	ID            string `xml:"id"`
	Active        string `xml:"active"`
	Protocol      string `xml:"protocol"`
	Host          string `xml:"host"`
	Port          string `xml:"port"`
	Username      string `xml:"username"`
	Password      string `xml:"password"`
	NonProxyHosts string `xml:"nonProxyHosts"`
}

type Mirror struct {
	ID       string `xml:"id"`
	Name     string `xml:"name"`
	URL      string `xml:"url"`
	MirrorOf string `xml:"mirrorOf"`
}

type settings struct {
	LocalRepository string          `xml:"localRepository"`
	Servers         []Server        `xml:"servers>server"`
	Profiles        []Profile       `xml:"profiles>profile"`
	ActiveProfiles  []string        `xml:"activeProfiles>activeProfile"`
	Proxies         []Proxy         `xml:"proxies>proxy"`
	Mirrors         []Mirror        `xml:"mirrors>mirror"`
	Repositories    []pomRepository `xml:"repositories>repository"` // Repositories declared at the root of settings.xml (Maven 4)
}

func (s settings) effectiveRepositories() []repository {
	var pomRepos []pomRepository
	for _, profile := range s.Profiles {
		if slices.Contains(s.ActiveProfiles, profile.ID) || profile.ActiveByDefault {
			pomRepos = append(pomRepos, profile.Repositories...)
		}
	}

	// Repositories declared at the root of settings.xml (Maven 4).
	// Profile repositories are appended first so they win when deduplicating by ID.
	pomRepos = append(pomRepos, s.Repositories...)

	pomRepos = lo.UniqBy(pomRepos, func(r pomRepository) string {
		return r.ID
	})

	// mvn takes repositories from settings in reverse order
	// cf. https://github.com/aquasecurity/trivy/issues/7807#issuecomment-2541485152
	mutable.Reverse(pomRepos)

	return resolvePomRepos(s.Servers, pomRepos)
}

func (s settings) effectiveProxies(protocol, hostname string) []Proxy {
	var proxies []Proxy
	for _, proxy := range s.Proxies {
		if !proxy.isActive() || !strings.EqualFold(proxy.Protocol, protocol) {
			continue
		}
		if hostname != "" && proxy.isNonProxyHost(hostname) {
			continue
		}
		proxies = append(proxies, proxy)
	}
	return proxies
}

func (p Proxy) isActive() bool {
	return p.Active == trueString || p.Active == ""
}

func (p Proxy) isNonProxyHost(host string) bool {
	if p.NonProxyHosts == "" {
		return false
	}

	hosts := strings.SplitSeq(p.NonProxyHosts, "|")
	for h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}

		matched, err := path.Match(strings.ToLower(h), strings.ToLower(host))
		if err == nil && matched {
			return true
		}
	}
	return false
}

// readSettings loads Maven settings and merges them by precedence.
// Maven resolves settings in the order global < project < user, so user
// settings are dominant, followed by project settings, then global.
// https://maven.apache.org/ref/4-LATEST/api/maven-api-settings/settings.html
//
// projectDir is the directory of the POM being parsed. When it contains a
// .mvn/settings.xml file (Maven 4 project-specific settings), it is merged
// between the user and global settings.
func readSettings(projectDir string) settings {
	s := settings{}

	userSettingsPath := filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
	if userSettings, err := openSettings(userSettingsPath); err == nil {
		s = userSettings
	}

	// Maven 4 project-specific settings (${session.rootdir}/.mvn/settings.xml).
	if projectDir != "" {
		projectSettingsPath := filepath.Join(projectDir, ".mvn", "settings.xml")
		if projectSettings, err := openSettings(projectSettingsPath); err == nil {
			mergeSettings(&s, projectSettings)
		}
	}

	// Some package managers use this path by default
	mavenHome := "/usr/share/maven"
	if mHome := os.Getenv("MAVEN_HOME"); mHome != "" {
		mavenHome = mHome
	}
	globalSettingsPath := filepath.Join(mavenHome, "conf", "settings.xml")
	if globalSettings, err := openSettings(globalSettingsPath); err == nil {
		mergeSettings(&s, globalSettings)
	}

	return s
}

// mergeSettings merges lower-priority settings into s. Values already present
// in s take precedence, so callers must merge from highest to lowest priority.
// https://maven.apache.org/settings.html#quick-overview
func mergeSettings(s *settings, lower settings) {
	if s.LocalRepository == "" {
		s.LocalRepository = lower.LocalRepository
	}
	s.Servers = lo.UniqBy(append(s.Servers, lower.Servers...), func(server Server) string {
		return server.ID
	})
	s.Profiles = lo.UniqBy(append(s.Profiles, lower.Profiles...), func(p Profile) string {
		return p.ID
	})
	s.ActiveProfiles = lo.Uniq(append(s.ActiveProfiles, lower.ActiveProfiles...))
	s.Proxies = lo.UniqBy(append(s.Proxies, lower.Proxies...), func(p Proxy) string {
		return p.ID
	})
	s.Mirrors = lo.UniqBy(append(s.Mirrors, lower.Mirrors...), func(m Mirror) string {
		return m.ID
	})
	// Root-level repositories are a Maven 4 addition. Merge them only when
	// present so that settings without them keep a nil slice.
	if len(s.Repositories) > 0 || len(lower.Repositories) > 0 {
		s.Repositories = lo.UniqBy(append(s.Repositories, lower.Repositories...), func(r pomRepository) string {
			return r.ID
		})
	}
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

	for i, repo := range s.Repositories {
		s.Repositories[i].ID = evaluateVariable(repo.ID, nil, nil)
		s.Repositories[i].Name = evaluateVariable(repo.Name, nil, nil)
		s.Repositories[i].URL = evaluateVariable(repo.URL, nil, nil)
	}

	for i, proxy := range s.Proxies {
		s.Proxies[i].ID = evaluateVariable(proxy.ID, nil, nil)
		s.Proxies[i].Active = evaluateVariable(proxy.Active, nil, nil)
		s.Proxies[i].Protocol = evaluateVariable(proxy.Protocol, nil, nil)
		s.Proxies[i].Host = evaluateVariable(proxy.Host, nil, nil)
		s.Proxies[i].Port = evaluateVariable(proxy.Port, nil, nil)
		s.Proxies[i].Username = evaluateVariable(proxy.Username, nil, nil)
		s.Proxies[i].Password = evaluateVariable(proxy.Password, nil, nil)
		s.Proxies[i].NonProxyHosts = evaluateVariable(proxy.NonProxyHosts, nil, nil)
	}

	for i, m := range s.Mirrors {
		s.Mirrors[i].ID = evaluateVariable(m.ID, nil, nil)
		s.Mirrors[i].Name = evaluateVariable(m.Name, nil, nil)
		s.Mirrors[i].URL = evaluateVariable(m.URL, nil, nil)
		s.Mirrors[i].MirrorOf = evaluateVariable(m.MirrorOf, nil, nil)
	}
}
