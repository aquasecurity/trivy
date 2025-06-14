package pom

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/net/html/charset"
)

type Server struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}

type settings struct {
	LocalRepository string   `xml:"localRepository"`
	Servers         []Server `xml:"servers>server"`
}

// e.g. ${env.USERNAME}. Note the capturing group after "${env." -
// this will be used to extract the variable name for the env lookup
var mavenEnvPattern = regexp.MustCompile(`\$\{env\.([A-Za-z_][A-Za-z0-9_]*)\}`)

// serverFound checks that servers already contain server.
// Maven compares servers by ID only.
func serverFound(servers []Server, id string) bool {
	for _, server := range servers {
		if server.ID == id {
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
		// Maven checks user servers first, then global servers
		for _, server := range globalSettings.Servers {
			if !serverFound(s.Servers, server.ID) {
				s.Servers = append(s.Servers, server)
			}
		}
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
	s.LocalRepository = replacePlaceholdersWithEnvValues(s.LocalRepository)
	for i, server := range s.Servers {
		s.Servers[i].ID = replacePlaceholdersWithEnvValues(server.ID)
		s.Servers[i].Username = replacePlaceholdersWithEnvValues(server.Username)
		s.Servers[i].Password = replacePlaceholdersWithEnvValues(server.Password)
	}
}

func replacePlaceholdersWithEnvValues(s string) string {
	return mavenEnvPattern.ReplaceAllStringFunc(s, func(match string) string {
		submatches := mavenEnvPattern.FindStringSubmatch(match)
		return os.Getenv(submatches[1])
	})
}
