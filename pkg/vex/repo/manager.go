package repo

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const (
	defaultVEXHubURL = "https://github.com/aquasecurity/vexhub"
	vexDir           = "vex"
	repoDir          = "repositories"
)

type ManagerOption func(indexer *Manager)

func WithWriter(w io.Writer) ManagerOption {
	return func(manager *Manager) {
		manager.w = w
	}
}

type Config struct {
	Repositories []Repository `json:"repositories"`
}

func (c *Config) EnabledRepositories() []Repository {
	return lo.Filter(c.Repositories, func(r Repository, _ int) bool {
		return r.Enabled
	})
}

type Options struct {
	Insecure bool
}

// Manager manages the repositories
type Manager struct {
	w          io.Writer
	configFile string
	cacheDir   string
}

func NewManager(cacheRoot string, opts ...ManagerOption) *Manager {
	m := &Manager{
		w:          os.Stdout,
		configFile: filepath.Join(fsutils.TrivyHomeDir(), vexDir, "repository.yaml"),
		cacheDir:   filepath.Join(cacheRoot, vexDir),
	}
	for _, opt := range opts {
		opt(m)
	}

	return m
}

func (m *Manager) writeConfig(conf Config) error {
	if err := os.MkdirAll(filepath.Dir(m.configFile), 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}
	f, err := os.Create(m.configFile)
	if err != nil {
		return xerrors.Errorf("failed to create a file: %w", err)
	}
	defer f.Close()

	e := yaml.NewEncoder(f)
	e.SetIndent(2)
	if err = e.Encode(conf); err != nil {
		return xerrors.Errorf("JSON encode error: %w", err)
	}

	return nil
}

func (m *Manager) Config(ctx context.Context) (Config, error) {
	if !fsutils.FileExists(m.configFile) {
		log.DebugContext(ctx, "No repository config found", log.String("path", m.configFile))
		if err := m.Init(ctx); err != nil {
			return Config{}, xerrors.Errorf("unable to initialize the VEX repository config: %w", err)
		}
	}

	f, err := os.Open(m.configFile)
	if err != nil {
		return Config{}, xerrors.Errorf("unable to open a file: %w", err)
	}
	defer f.Close()

	var conf Config
	if err = yaml.NewDecoder(f).Decode(&conf); err != nil {
		return conf, xerrors.Errorf("unable to decode metadata: %w", err)
	}

	for i, repo := range conf.Repositories {
		conf.Repositories[i].dir = filepath.Join(m.cacheDir, repoDir, repo.Name)
	}

	return conf, nil
}

func (m *Manager) Init(ctx context.Context) error {
	if fsutils.FileExists(m.configFile) {
		log.InfoContext(ctx, "The configuration file already exists", log.String("path", m.configFile))
		return nil
	}

	err := m.writeConfig(Config{
		Repositories: []Repository{
			{
				Name:    "default",
				URL:     defaultVEXHubURL,
				Enabled: true,
			},
		},
	})
	if err != nil {
		return xerrors.Errorf("failed to write the default config: %w", err)
	}
	log.InfoContext(ctx, "The default repository config has been created", log.FilePath(m.configFile))
	return nil
}

func (m *Manager) DownloadRepositories(ctx context.Context, names []string, opts Options) error {
	conf, err := m.Config(ctx)
	if err != nil {
		return xerrors.Errorf("unable to read config: %w", err)
	}

	repos := lo.Filter(conf.EnabledRepositories(), func(r Repository, _ int) bool {
		return len(names) == 0 || slices.Contains(names, r.Name)
	})
	if len(repos) == 0 {
		log.WarnContext(ctx, "No enabled repositories found in config", log.String("path", m.configFile))
		return nil
	}

	for _, repo := range repos {
		if err = repo.Update(ctx, opts); err != nil {
			return xerrors.Errorf("failed to update the repository: %w", err)
		}
	}
	return nil
}

// List returns a list of all repositories in the configuration
func (m *Manager) List(ctx context.Context) error {
	conf, err := m.Config(ctx)
	if err != nil {
		return xerrors.Errorf("unable to read config: %w", err)
	}

	var output strings.Builder

	output.WriteString(fmt.Sprintf("VEX Repositories (config: %s)\n\n", m.configFile))

	if len(conf.Repositories) == 0 {
		output.WriteString("No repositories configured.\n")
	} else {
		for _, repo := range conf.Repositories {
			status := "Enabled"
			if !repo.Enabled {
				status = "Disabled"
			}
			output.WriteString(fmt.Sprintf("- Name: %s\n  URL: %s\n  Status: %s\n\n", repo.Name, repo.URL, status))
		}
	}

	if _, err = io.WriteString(m.w, output.String()); err != nil {
		return xerrors.Errorf("failed to write output: %w", err)
	}

	return nil
}

func (m *Manager) Clear() error {
	return os.RemoveAll(m.cacheDir)
}
