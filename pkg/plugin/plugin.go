package plugin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// Plugin represents a plugin.
type Plugin struct {
	Name        string     `yaml:"name"`
	Repository  string     `yaml:"repository"`
	Version     string     `yaml:"version"`
	Summary     string     `yaml:"summary"`
	Usage       string     `yaml:"usage"` // Deprecated: Use summary instead
	Description string     `yaml:"description"`
	Platforms   []Platform `yaml:"platforms"`

	// Installed holds the metadata about installation
	Installed Installed `yaml:"installed"`

	// dir points to the directory where the plugin is installed
	dir string
}

type Installed struct {
	Platform Selector `yaml:"platform"`
}

// Platform represents where the execution file exists per platform.
type Platform struct {
	Selector *Selector
	URI      string
	Bin      string
}

// Selector represents the environment.
type Selector struct {
	OS   string `yaml:"os"`
	Arch string `yaml:"arch"`
}

type Options struct {
	Args     []string
	Stdin    io.Reader // For output plugin
	Platform ftypes.Platform
	Insecure bool
}

func (p *Plugin) Cmd(ctx context.Context, opts Options) (*exec.Cmd, error) {
	platform, err := p.selectPlatform(ctx, opts)
	if err != nil {
		return nil, xerrors.Errorf("platform selection error: %w", err)
	}

	execFile := filepath.Join(p.Dir(), platform.Bin)

	cmd := exec.CommandContext(ctx, execFile, opts.Args...)
	cmd.Stdin = os.Stdin
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	return cmd, nil
}

type Wait func() error

// Start starts the plugin
//
// After a successful call to Start the Wait method must be called.
func (p *Plugin) Start(ctx context.Context, opts Options) (Wait, error) {
	cmd, err := p.Cmd(ctx, opts)
	if err != nil {
		return nil, xerrors.Errorf("cmd: %w", err)
	}

	if err = cmd.Start(); err != nil {
		return nil, xerrors.Errorf("plugin start: %w", err)
	}
	return cmd.Wait, nil
}

// Run runs the plugin
func (p *Plugin) Run(ctx context.Context, opts Options) error {
	cmd, err := p.Cmd(ctx, opts)
	if err != nil {
		return xerrors.Errorf("cmd: %w", err)
	}

	// If an error is found during the execution of the plugin, figure
	// out if the error was from not being able to execute the plugin or
	// an error set by the plugin itself.
	if err = cmd.Run(); err != nil {
		var execError *exec.ExitError
		if errors.As(err, &execError) {
			return &types.ExitError{
				Code: execError.ExitCode(),
			}
		}
		return xerrors.Errorf("plugin exec: %w", err)
	}
	return nil
}

func (p *Plugin) selectPlatform(ctx context.Context, opts Options) (Platform, error) {
	// These values are only filled in during unit tests.
	goos := runtime.GOOS
	if opts.Platform.Platform != nil && opts.Platform.OS != "" {
		goos = opts.Platform.OS
	}
	goarch := runtime.GOARCH
	if opts.Platform.Platform != nil && opts.Platform.Architecture != "" {
		goarch = opts.Platform.Architecture
	}

	for _, platform := range p.Platforms {
		if platform.Selector == nil {
			return platform, nil
		}

		selector := platform.Selector
		if (selector.OS == "" || goos == selector.OS) &&
			(selector.Arch == "" || goarch == selector.Arch) {
			log.DebugContext(ctx, "Platform found",
				log.String("os", selector.OS), log.String("arch", selector.Arch))
			return platform, nil
		}
	}
	return Platform{}, xerrors.New("platform not found")
}

func (p *Plugin) install(ctx context.Context, dst, pwd string, opts Options) error {
	log.DebugContext(ctx, "Installing the plugin...", log.String("path", dst))
	platform, err := p.selectPlatform(ctx, opts)
	if err != nil {
		return xerrors.Errorf("platform selection error: %w", err)
	}
	p.Installed.Platform = lo.FromPtr(platform.Selector)

	log.DebugContext(ctx, "Downloading the execution file...", log.String("uri", platform.URI))
	if _, err = downloader.Download(ctx, platform.URI, dst, pwd, downloader.Options{Insecure: opts.Insecure}); err != nil {
		return xerrors.Errorf("unable to download the execution file (%s): %w", platform.URI, err)
	}
	return nil
}

func (p *Plugin) Dir() string {
	if p.dir != "" {
		return p.dir
	}
	return filepath.Join(fsutils.TrivyHomeDir(), pluginsDir, p.Name)
}
