package repo

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// const defaultVEXHubURL = "git@github.com:aquasecurity/vexhub.git"
const defaultVEXHubURL = "https://github.com/aquasecurity/vuln-list-update.git"

type ManagerOption func(indexer *Manager)

func WithWriter(w io.Writer) ManagerOption {
	return func(manager *Manager) {
		manager.w = w
	}
}

func WithLogger(logger *log.Logger) ManagerOption {
	return func(manager *Manager) {
		manager.logger = logger
	}
}

type Config struct {
	Repositories []Repository `json:"repositories"`
}

type Repository struct {
	Name string
	URL  string
	DB   string `yaml:",omitempty"` // TODO: support pre-built DB
}

type Options struct {
	Insecure bool
}

// Manager manages the plugins
type Manager struct {
	w          io.Writer
	indexURL   string
	logger     *log.Logger
	configFile string
	repoDir    string
}

func NewManager(opts ...ManagerOption) *Manager {
	root := filepath.Join(fsutils.TrivyHomeDir(), "vex")
	m := &Manager{
		w:          os.Stdout,
		logger:     log.WithPrefix("vex"),
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

func (m *Manager) readConfig() (Config, error) {
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
	return conf, nil
}

func (m *Manager) Init(ctx context.Context) error {
	if fsutils.FileExists(m.configFile) {
		m.logger.InfoContext(ctx, "The configuration file already exists", log.String("path", m.configFile))
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

func (m *Manager) Update(ctx context.Context, names []string, opts Options) error {
	conf, err := m.readConfig()
	if err != nil {
		return xerrors.Errorf("unable to read config: %w", err)
	} else if len(conf.Repositories) == 0 {
		return xerrors.Errorf("no repositories found in config: %s", m.configFile)
	}

	for _, repo := range conf.Repositories {
		if len(names) > 0 && !slices.Contains(names, repo.Name) {
			continue
		}
		m.logger.InfoContext(ctx, "Updating the repository...", log.String("name", repo.Name), log.String("url", repo.URL))
		if err = m.download(ctx, repo, opts); err != nil {
			return xerrors.Errorf("failed to update the repository: %w", err)
		}
	}
	return nil
}

func (m *Manager) download(ctx context.Context, repo Repository, opts Options) error {
	// Force git protocol
	// cf. https://github.com/hashicorp/go-getter/blob/5a63fd9c0d5b8da8a6805e8c283f46f0dacb30b3/README.md#forced-protocol
	url := "git::" + repo.URL + "?depth=1"

	dst := filepath.Join(m.repoDir, repo.Name)
	if fsutils.DirExists(dst) {
		defaultBranch, err := findDefaultBranch(dst)
		if err != nil {
			m.logger.DebugContext(ctx, "failed to find the default branch", log.String("path", dst), log.Err(err))
			defaultBranch = "main"
		}
		url += "&ref=" + defaultBranch
	}

	m.logger.DebugContext(ctx, "Downloading the repository...", log.String("url", url), log.String("dst", dst))
	if err := downloader.Download(ctx, url, dst, ".", opts.Insecure); err != nil {
		return xerrors.Errorf("failed to download the repository: %w", err)
	}
	return nil
}

func findDefaultBranch(repoPath string) (string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", err
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", err
	}

	refs, err := remote.List(&git.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, ref := range refs {
		if ref.Name() == "HEAD" {
			if ref.Type() == plumbing.SymbolicReference {
				return ref.Target().Short(), nil
			}
		}
	}
	return "", fmt.Errorf("HEAD reference not found")
}
