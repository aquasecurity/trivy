package pom

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

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

type Mirror struct {
	ID       string `xml:"id"`
	Name     string `xml:"name"`
	URL      string `xml:"url"`
	MirrorOf string `xml:"mirrorOf"`
}

func (m Mirror) GetID() string { return m.ID }

type activation struct {
	ActiveByDefault bool `xml:"activeByDefault"`
}

type settings struct {
	LocalRepository string    `xml:"localRepository"`
	Servers         []Server  `xml:"servers>server"`
	Profiles        []Profile `xml:"profiles>profile"`
	ActiveProfiles  []string  `xml:"activeProfiles>activeProfile"`
	Mirrors         []Mirror  `xml:"mirrors>mirror"`
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
		// Merge mirrors
		for _, mirror := range globalSettings.Mirrors {
			if !containsByID(s.Mirrors, mirror.ID) {
				logger.Debug("Adding mirror from global settings", log.String("id", mirror.ID))
				s.Mirrors = append(s.Mirrors, mirror)
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
	for i, mirror := range s.Mirrors {
		s.Mirrors[i].ID = evaluateVariable(mirror.ID, nil, nil)
		s.Mirrors[i].Name = evaluateVariable(mirror.Name, nil, nil)
		s.Mirrors[i].URL = evaluateVariable(mirror.URL, nil, nil)
		s.Mirrors[i].MirrorOf = evaluateVariable(mirror.MirrorOf, nil, nil)
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
	var repositories []repository
	for _, activeProfile := range s.getActiveProfiles() {
		repositories = append(repositories, activeProfile.Repositories...)
	}
	return repositories
}

// getEffectiveRepositories returns a list of effective repositories.
// Gets repositories for all active profiles.
// Applying mirror settings for repositories if applicable.
// Keeping only unique repositories in the result.
// This is on settings.xml level, not considering repositories from pom.xml,
// which need to be combined in a separate step.
func (s *settings) getEffectiveRepositories() []repository {
	repositories := s.getRepositoriesForActiveProfiles()
	applyMirrorSettingsForRepositories(repositories, s)
	return lo.Uniq(repositories)
}

// findMirrorForRepository returns the mirror configured for the given repository ID, if any.
// Specific mirrors (matching the exact repository ID) take precedence over generic ones (mirrorOf="*").
// Note: Patterns like "external:*" in mirrorOf are not currently supported.
// See: https://maven.apache.org/guides/mini/guide-mirror-settings.html
func (s *settings) findMirrorForRepository(repositoryID string) *Mirror {
	logger := log.WithPrefix("pom")

	var specificMirrors []Mirror
	var genericMirrors []Mirror

	for _, mirror := range s.Mirrors {
		mirrorOfs := strings.Split(mirror.MirrorOf, ",")
		for i := range mirrorOfs {
			mirrorOfs[i] = strings.TrimSpace(mirrorOfs[i])
		}

		switch {
		case slices.Contains(mirrorOfs, fmt.Sprintf("!%s", repositoryID)):
			logMirrorDetection(logger, "Detected mirror that may **not** be used for repository", repositoryID, mirror, mirrorOfs)
			continue
		case slices.Contains(mirrorOfs, repositoryID):
			logMirrorDetection(logger, "Detected specific mirror for repository", repositoryID, mirror, mirrorOfs)
			specificMirrors = append(specificMirrors, mirror)
		case slices.Contains(mirrorOfs, "*") || slices.Contains(mirrorOfs, "external:*"):
			logMirrorDetection(logger, "Detected generic mirror that may be used for repository", repositoryID, mirror, mirrorOfs)
			genericMirrors = append(genericMirrors, mirror)
		}
	}

	if mirror := selectMirrorAndLog(logger, "specific", repositoryID, specificMirrors); mirror != nil {
		return mirror
	}
	if mirror := selectMirrorAndLog(logger, "generic", repositoryID, genericMirrors); mirror != nil {
		return mirror
	}

	logger.Debug("No mirror found for repository", log.String("repositoryID", repositoryID))
	return nil
}

// logMirrorDetection is a helper for logging mirror detection events, to reduce code duplication.
func logMirrorDetection(logger *log.Logger, message, repositoryID string, mirror Mirror, mirrorOfs []string) {
	logger.Debug(message,
		log.String("repositoryID", repositoryID),
		log.String("mirror.ID", mirror.ID),
		log.Any("mirrorOfs", mirrorOfs))
}

// selectMirrorAndLog selects the first mirror from the provided slice, logging appropriately.
func selectMirrorAndLog(logger *log.Logger, kind, repositoryID string, mirrors []Mirror) *Mirror {
	if len(mirrors) == 0 {
		return nil
	}
	if len(mirrors) > 1 {
		logger.Debug(fmt.Sprintf("Multiple %s mirrors found for repository, selecting the first one", kind),
			log.String("repositoryID", repositoryID),
			log.String("selectedMirrorID", mirrors[0].ID),
			log.Int("mirrorCount", len(mirrors)))
	}
	logger.Debug(fmt.Sprintf("Selecting %s mirror for repository", kind),
		log.String("repositoryID", repositoryID),
		log.String("mirror.ID", mirrors[0].ID))
	return &mirrors[0]
}
