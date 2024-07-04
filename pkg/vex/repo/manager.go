package repo

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const (
	// const defaultVEXHubURL = "git@github.com:aquasecurity/vexhub.git"
	defaultVEXHubURL = "https://github.com/aquasecurity/vuln-list-update.git"
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

type Options struct {
	Insecure bool
}

// Manager manages the plugins
type Manager struct {
	w          io.Writer
	indexURL   string
	configFile string
	repoDir    string
}

func NewManager(opts ...ManagerOption) *Manager {
	root := filepath.Join(fsutils.TrivyHomeDir(), "vex")
	m := &Manager{
		w:          os.Stdout,
		configFile: filepath.Join(root, "config.yaml"),
		repoDir:    filepath.Join(root, "repositories"),
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

func (m *Manager) Config() (Config, error) {
	if !fsutils.FileExists(m.configFile) {
		return Config{}, xerrors.Errorf("config file not found, run 'trivy vex repo init' first")
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

	for i := range conf.Repositories {
		conf.Repositories[i].dir = m.repoDir
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
				Name: "default",
				URL:  defaultVEXHubURL,
			},
		},
	})
	if err != nil {
		return xerrors.Errorf("failed to write the default config: %w", err)
	}
	log.InfoContext(ctx, "The default configuration file has been created", log.FilePath(m.configFile))
	return nil
}

func (m *Manager) UpdateManifest(ctx context.Context, names []string, opts Options) error {
	conf, err := m.Config()
	if err != nil {
		return xerrors.Errorf("unable to read config: %w", err)
	} else if len(conf.Repositories) == 0 {
		return xerrors.Errorf("no repositories found in config: %s", m.configFile)
	}

	for _, repo := range conf.Repositories {
		if len(names) > 0 && !slices.Contains(names, repo.Name) {
			continue
		}
		log.InfoContext(ctx, "Updating the repository...", log.String("name", repo.Name), log.String("url", repo.URL))
		if err = repo.downloadManifest(ctx, opts); err != nil {
			return xerrors.Errorf("failed to update the repository: %w", err)
		}
	}
	return nil
}
