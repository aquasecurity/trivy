package pom

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"slices"

	"github.com/samber/lo"
	"golang.org/x/net/html/charset"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Server struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}

func (s Server) GetID() string { return s.ID }

type Profile struct {
	ID           string       `xml:"id"`
	Repositories []repository `xml:"repositories>repository"`
	Activation   activation   `xml:"activation"`
}

func (p Profile) GetID() string { return p.ID }

type activation struct {
	ActiveByDefault bool `xml:"activeByDefault"`
}

type settings struct {
	LocalRepository string    `xml:"localRepository"`
	Servers         []Server  `xml:"servers>server"`
	Profiles        []Profile `xml:"profiles>profile"`
	ActiveProfiles  []string  `xml:"activeProfiles>activeProfile"`
}

func readSettings() settings {
	s := settings{}

	logger := log.WithPrefix("pom")

	userSettingsPath := filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
	userSettings, err := openSettings(userSettingsPath)
	if err == nil {
		logger.Debug("Using user settings file", log.String("userSettingsPath", userSettingsPath))
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
		logger.Debug("Using global settings file",
			log.String("globalSettingsPath", globalSettingsPath))

		// We need to merge global and user settings. User settings being dominant.
		// https://maven.apache.org/settings.html#quick-overview
		if s.LocalRepository == "" {
			logger.Debug("Using local repository from global settings",
				log.String("localRepository", globalSettings.LocalRepository))
			s.LocalRepository = globalSettings.LocalRepository
		}
		// Maven checks user servers first, then global servers
		for _, server := range globalSettings.Servers {
			if !containsByID(s.Servers, server.ID) {
				logger.Debug("Adding server from global settings", log.String("id", server.ID))
				s.Servers = append(s.Servers, server)
			}
		}
		// Merge profiles
		for _, profile := range globalSettings.Profiles {
			if !containsByID(s.Profiles, profile.ID) {
				logger.Debug("Adding profile from global settings", log.String("id", profile.ID))
				s.Profiles = append(s.Profiles, profile)
			}
		}
		// Merge active profiles
		for _, activeProfile := range globalSettings.ActiveProfiles {
			if !slices.Contains(s.ActiveProfiles, activeProfile) {
				logger.Debug("Adding active profile from global settings",
					log.String("activeProfile", activeProfile))
				s.ActiveProfiles = append(s.ActiveProfiles, activeProfile)
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
}

// getActiveProfiles returns a list of active profiles from the settings.
// It checks the activeProfiles as well as the activeByDefault in each profile.
// Currently, the property (ActivationProperty), os (ActivationOS), file (ActivationFile) mechanisms are not supported.
func (s *settings) getActiveProfiles() []Profile {
	logger := log.WithPrefix("pom")
	var profiles []Profile

	if len(s.Profiles) == 0 {
		logger.Debug("No profiles defined in settings")
		return profiles
	}

	logger.Debug("Active profiles specified in settings", log.Any("activeProfiles", s.ActiveProfiles))

	for _, profile := range s.Profiles {
		if slices.Contains(s.ActiveProfiles, profile.ID) {
			logger.Debug("Profile is active by means of activeProfiles", log.String("id", profile.ID))
			profiles = append(profiles, profile)
		} else if profile.Activation.ActiveByDefault {
			logger.Debug("Profile is active by default", log.String("id", profile.ID))
			profiles = append(profiles, profile)
		}
	}
	return lo.UniqBy(profiles, func(p Profile) string {
		return p.ID
	})
}

// getRepositoriesForActiveProfiles returns a list of repositories for all active profiles.
// This is on settings.xml level, not considering repositories from pom.xml,
// which need to be combined in a separate step.
func (s *settings) getRepositoriesForActiveProfiles() []repository {
	logger := log.WithPrefix("pom")
	var repositories []repository
	for _, activeProfile := range s.getActiveProfiles() {
		for _, repo := range activeProfile.Repositories {
			logger.Debug("Active profile has repository",
				log.String("profileID", activeProfile.ID), log.String("repoID", repo.ID), log.String("url", repo.URL))

			if !repo.Releases.IsEnabled() && !repo.Snapshots.IsEnabled() {
				logger.Debug("Skipping repository as both releases and snapshots have been explicitly disabled",
					log.String("id", repo.ID), log.String("url", repo.URL))
				continue
			}

			repositories = append(repositories, repo)
		}
	}
	return repositories
}

// getEffectiveRepositories returns a list of effective repositories.
// Gets repositories for all active profiles.
// Keeping only unique repositories in the result.
// This is on settings.xml level, not considering repositories from pom.xml,
// which need to be combined in a separate step.
func (s *settings) getEffectiveRepositories() []repository {
	repositories := s.getRepositoriesForActiveProfiles()
	return lo.Uniq(repositories)
}
