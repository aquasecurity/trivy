package pom

import (
	"encoding/xml"
	"os"
	"path/filepath"

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

	s := settings{}
	decoder := xml.NewDecoder(f)
	decoder.CharsetReader = charset.NewReaderLabel
	if err = decoder.Decode(&s); err != nil {
		return settings{}, err
	}
	return s, nil
}
