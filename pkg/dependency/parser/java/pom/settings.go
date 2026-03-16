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

type settings struct {
	LocalRepository string    `xml:"localRepository"`
	Servers         []Server  `xml:"servers>server"`
	Profiles        []Profile `xml:"profiles>profile"`
	ActiveProfiles  []string  `xml:"activeProfiles>activeProfile"`
	Proxies         []Proxy   `xml:"proxies>proxy"`
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

		// Merge proxies
		s.Proxies = lo.UniqBy(append(s.Proxies, globalSettings.Proxies...), func(p Proxy) string {
			return p.ID
		})
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
}
