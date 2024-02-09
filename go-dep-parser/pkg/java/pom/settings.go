package pom

import (
	"encoding/xml"
	"os"
	"path/filepath"

	"golang.org/x/net/html/charset"
)

type settings struct {
	LocalRepository string `xml:"localRepository"`
}

func readSettings() settings {
	userSettingsPath := filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
	userSettings, err := openSettings(userSettingsPath)
	if err == nil && userSettings.LocalRepository != "" {
		return userSettings
	}

	globalSettingsPath := filepath.Join(os.Getenv("MAVEN_HOME"), "conf", "settings.xml")
	globalSettings, err := openSettings(globalSettingsPath)
	if err == nil && globalSettings.LocalRepository != "" {
		return globalSettings
	}

	return settings{}
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
