package repo

import (
	"context"
	"errors"
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
	defaultVEXHubURL = "https://github.com/aquasecurity/vexhub"
	vexDir           = "vex"
	repoDir          = "repositories"
)

var ErrNoConfig = errors.New("no config found")

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

	for i, r := range conf.Repositories {
		conf.Repositories[i].dir = filepath.Join(m.cacheDir, repoDir, r.Name)
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
	log.InfoContext(ctx, "The default repository config has been created", log.FilePath(m.configFile))
	return nil
}

func (m *Manager) DownloadRepositories(ctx context.Context, names []string, opts Options) error {
	conf, err := m.Config(ctx)
	if err != nil {
		return xerrors.Errorf("unable to read config: %w", err)
	} else if len(conf.Repositories) == 0 {
		return xerrors.Errorf("no repositories found in config: %s", m.configFile)
	}

	for _, repo := range conf.Repositories {
		if len(names) > 0 && !slices.Contains(names, repo.Name) {
			continue
		}
		if err = repo.Update(ctx, opts); err != nil {
			return xerrors.Errorf("failed to update the repository: %w", err)
		}
	}
	return nil
}

func (m *Manager) Clear() error {
	return os.RemoveAll(m.cacheDir)
}
