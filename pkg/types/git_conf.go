package types

import (
	"github.com/caarlos0/env/v6"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/remote"
	"github.com/aquasecurity/trivy/pkg/log"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

type GitConfig struct {
	Branch          string `env:"TRIVY_GIT_BRANCH"`
	Tag             string `env:"TRIVY_GIT_TAG"`
	Commit          string `env:"TRIVY_GIT_COMMIT"`
	ParentDirectory string `env:"TRIVY_GIT_CLONE_PARENT_DIRECTORY"`
	Username        string `env:"TRIVY_GIT_USERNAME"`
	Password        string `env:"TRIVY_GIT_PASSWORD"`
	KeyPath         string `env:"TRIVY_GIT_KEY_PATH"`
}

type LogWriter struct{}

func (l *LogWriter) Write(b []byte) (int, error) {
	log.Logger.Debugf(string(b))
	return len(b), nil
}

func GetGitOption(url string) (remote.Remote, error) {
	cfg := GitConfig{}
	if err := env.Parse(&cfg); err != nil {
		return remote.Remote{}, xerrors.Errorf("unable to parse environment variables: %w", err)
	}

	endpoint, err := transport.NewEndpoint(url)
	if err != nil {
		return remote.Remote{}, xerrors.Errorf("unable to parse url: %w", err)
	}

	// check for creds in endpoint
	if cfg.Username == "" && endpoint.User != "" {
		cfg.Username = endpoint.User
	}
	if cfg.Password == "" && endpoint.Password != "" {
		cfg.Password = endpoint.Password
	}

	// specify reference to clone
	var ref plumbing.ReferenceName
	if cfg.Branch != "" {
		ref = plumbing.NewBranchReferenceName(cfg.Branch)
	} else if cfg.Tag != "" {
		ref = plumbing.NewTagReferenceName(cfg.Tag)
	}

	// avoid full clones
	depth := 1
	singleBranch := true
	if cfg.Commit != "" {
		depth = 0
		singleBranch = false
	}

	// configure SSH key auth
	var auth ssh.AuthMethod
	if cfg.KeyPath != "" {
		auth, err = ssh.NewPublicKeysFromFile(cfg.Username, cfg.KeyPath, cfg.Password)
		if err != nil {
			return remote.Remote{}, xerrors.Errorf("unable to parse private key: %w", err)
		}
	} else if cfg.Username != "" {
		auth, err = ssh.NewSSHAgentAuth(cfg.Username)
		if err != nil {
			return remote.Remote{}, xerrors.Errorf("unable to connect to ssh agent: %w", err)
		}
	}

	logWriter := &LogWriter{}
	cloneOpts := &git.CloneOptions{
		URL:           url,
		ReferenceName: ref,
		Progress:      logWriter,
		Depth:         depth,
		SingleBranch:  singleBranch,
		Auth:          auth,
	}

	return remote.NewGitRemote(cfg.ParentDirectory, false, cfg.Commit, cloneOpts)
}
