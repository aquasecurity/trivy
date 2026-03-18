package pom

import (
	"encoding/xml"
	"os"
	"path"
	"path/filepath"

	"github.com/samber/lo"
	"github.com/samber/lo/mutable"
	"golang.org/x/net/html/charset"

	"github.com/aquasecurity/trivy/pkg/set"
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
	LocalRepository string          `xml:"localRepository"`
	Servers         []Server        `xml:"servers>server"`
	Repositories    []pomRepository `xml:"repositories>repository"`
	Profiles        []Profile       `xml:"profiles>profile"`
	ActiveProfiles  []string        `xml:"activeProfiles>activeProfile"`
}

func (s settings) effectiveRepositories() []repository {
	activeProfiles := set.New[string]()
	for _, profileID := range s.ActiveProfiles {
		activeProfiles.Append(profileID)
	}

	var pomRepos []pomRepository
	for _, profile := range s.Profiles {
		if isActiveProfile(profile, activeProfiles) {
			pomRepos = append(pomRepos, profile.Repositories...)
		}
	}
	pomRepos = append(pomRepos, s.Repositories...)
	pomRepos = lo.UniqBy(pomRepos, func(r pomRepository) string {
		return r.ID
	})

	// mvn takes repositories from settings in reverse order
	// cf. https://github.com/aquasecurity/trivy/issues/7807#issuecomment-2541485152
	mutable.Reverse(pomRepos)

	return resolvePomRepos(s.Servers, pomRepos)
}

func readSettings(rootFilePath string) settings {
	s := settings{}

	// Maven 4 applies settings in the following order:
	// global < project < user
	// https://github.com/apache/maven/blob/e6303aae3281e5e87151489bac9db9236dd7eb97/maven-embedder/src/main/java/org/apache/maven/cli/configuration/SettingsXmlConfigurationProcessor.java#L141-L143
	// https://maven.apache.org/settings.html#quick-overview
	for _, path := range []string{
		globalSettingsPath(),
		findProjectSettingsPath(rootFilePath),
		userSettingsPath(),
	} {
		loaded, err := openSettings(path)
		if err == nil {
			s = mergeSettings(loaded, s)
		}
	}

	return s
}

func mergeSettings(high, low settings) settings {
	out := high
	if out.LocalRepository == "" {
		out.LocalRepository = low.LocalRepository
	}

	// Maven servers
	out.Servers = lo.UniqBy(append(out.Servers, low.Servers...), func(server Server) string {
		return server.ID
	})

	// Maven repositories
	out.Repositories = lo.UniqBy(append(out.Repositories, low.Repositories...), func(repo pomRepository) string {
		return repo.ID
	})

	// Maven profiles
	out.Profiles = lo.UniqBy(append(out.Profiles, low.Profiles...), func(p Profile) string {
		return p.ID
	})

	//	Maven active profiles
	out.ActiveProfiles = lo.Uniq(append(out.ActiveProfiles, low.ActiveProfiles...))

	return out
}

func findProjectSettingsPath(rootFilePath string) string {
	if rootFilePath == "" {
		return ""
	}

	dir := filepath.Dir(rootFilePath)
	for {
		projectSettingsPath := filepath.Join(dir, ".mvn", "settings.xml")
		if _, err := os.Stat(projectSettingsPath); err == nil {
			return projectSettingsPath
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

func globalSettingsPath() string {
	mavenHome := "/usr/share/maven"
	if mHome := os.Getenv("MAVEN_HOME"); mHome != "" {
		mavenHome = mHome
	}
	return filepath.Join(mavenHome, "conf", "settings.xml")
}

func userSettingsPath() string {
	return filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
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
	expandServers(s.Servers)

	for i, profile := range s.Profiles {
		s.Profiles[i].ID = evaluateVariable(profile.ID, nil, nil)
		expandRepositories(s.Profiles[i].Repositories)
	}
	expandRepositories(s.Repositories)

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

func isActiveProfile(profile Profile, activeProfiles set.Set[string]) bool {
	if profile.ActiveByDefault {
		return true
	}
	return activeProfiles.Contains(profile.ID)
}

func expandServers(servers []Server) {
	for i, server := range servers {
		servers[i].ID = evaluateVariable(server.ID, nil, nil)
		servers[i].Username = evaluateVariable(server.Username, nil, nil)
		servers[i].Password = evaluateVariable(server.Password, nil, nil)
	}
}

func expandRepositories(repos []pomRepository) {
	for i, repo := range repos {
		repos[i].ID = evaluateVariable(repo.ID, nil, nil)
		repos[i].Name = evaluateVariable(repo.Name, nil, nil)
		repos[i].URL = evaluateVariable(repo.URL, nil, nil)
	}
}
