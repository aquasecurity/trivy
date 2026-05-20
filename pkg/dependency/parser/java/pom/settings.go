package pom

import (
	"encoding/xml"
	"net/url"
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

// matches reports whether this mirror should serve the given repository.
//
// mirrorOf is a comma-separated list of patterns. Supported tokens:
//   - "*"               — matches any repository
//   - "external:*"      — matches any non-local repository (not file:// and not
//     localhost/127.0.0.1/::1)
//   - "external:http:*" — same as external:* but only for the http scheme
//   - "<id>"            — matches a repository by exact id
//   - "!<id>"           — excludes a repository by id; an exclusion always wins
//     regardless of its position in the list, so "*,!internal"
//     and "!internal,*" behave identically.
//
// See https://maven.apache.org/guides/mini/guide-mirror-settings.html
func (m Mirror) matches(repoID, repoURL string) bool {
	patterns := strings.Split(m.MirrorOf, ",")

	// First pass: check exclusions. They take priority over any include token in
	// the same list, so we must scan them all before deciding the include result.
	for _, p := range patterns {
		if id, ok := strings.CutPrefix(strings.TrimSpace(p), "!"); ok && id == repoID {
			return false
		}
	}

	// Second pass: check include tokens. Parse the URL once for the
	// external/external:http checks; ignore url.Parse errors — isExternalRepo
	// treats a nil/empty URL as non-external.
	parsed, _ := url.Parse(repoURL)
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		// Skip empty entries (e.g. trailing comma) and exclusion tokens
		// already handled in the first pass.
		if p == "" || strings.HasPrefix(p, "!") {
			continue
		}
		switch p {
		case "*":
			return true
		case "external:*":
			if isExternalRepo(parsed) {
				return true
			}
		case "external:http:*":
			// external:http:* is external:* restricted to the http scheme;
			// https and other schemes must not match.
			if isExternalRepo(parsed) && parsed.Scheme == "http" {
				return true
			}
		default:
			// Any non-keyword token is treated as an exact repository id.
			if p == repoID {
				return true
			}
		}
	}
	return false
}

// isExternalRepo reports whether the URL points to an external repository.
// A repository is considered external when its scheme is not "file" and its
// hostname is not one of the loopback addresses (localhost, 127.0.0.1, ::1).
// A nil URL is treated as non-external so that unparsable URLs never trigger
// an external:* match.
func isExternalRepo(u *url.URL) bool {
	if u == nil || u.Scheme == "file" {
		return false
	}
	h := u.Hostname()
	return h != "localhost" && h != "127.0.0.1" && h != "::1"
}

type settings struct {
	LocalRepository string    `xml:"localRepository"`
	Servers         []Server  `xml:"servers>server"`
	Profiles        []Profile `xml:"profiles>profile"`
	ActiveProfiles  []string  `xml:"activeProfiles>activeProfile"`
	Proxies         []Proxy   `xml:"proxies>proxy"`
	Mirrors         []Mirror  `xml:"mirrors>mirror"`
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

		// Merge mirrors
		s.Mirrors = lo.UniqBy(append(s.Mirrors, globalSettings.Mirrors...), func(m Mirror) string {
			return m.ID
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

	// MirrorOf is a static matching rule, not a value — intentionally not expanded.
	for i, mirror := range s.Mirrors {
		s.Mirrors[i].ID = evaluateVariable(mirror.ID, nil, nil)
		s.Mirrors[i].Name = evaluateVariable(mirror.Name, nil, nil)
		s.Mirrors[i].URL = evaluateVariable(mirror.URL, nil, nil)
	}
}
