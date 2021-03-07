package plugin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/aquasecurity/trivy/pkg/utils"

	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
	yaml "gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	configFile  = "plugin.yaml"
	xdgDataHome = "XDG_DATA_HOME"
)

var (
	pluginsRelativeDir = filepath.Join(".trivy", "plugins")

	officialPlugins = map[string]string{
		"kubectl": "github.com/aquasecurity/trivy-plugin-kubectl",
	}
)

// Plugin represents a plugin.
type Plugin struct {
	Name        string     `yaml:"name"`
	Repository  string     `yaml:"repository"`
	Version     string     `yaml:"version"`
	Usage       string     `yaml:"usage"`
	Description string     `yaml:"description"`
	Platforms   []Platform `yaml:"platforms"`
}

type Platform struct {
	Selector *Selector
	URI      string
	Bin      string
}

type Selector struct {
	OS   string
	Arch string
}

func (p Plugin) Run(ctx context.Context, args []string) error {
	platform, err := p.selectPlatform()
	if err != nil {
		return xerrors.Errorf("platform selection error: %w", err)
	}

	execFile := filepath.Join(dir(), p.Name, platform.Bin)

	cmd := exec.CommandContext(ctx, execFile, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	// If an error is found during the execution of the plugin, figure
	// out if the error was from not being able to execute the plugin or
	// an error set by the plugin itself.
	if err = cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return xerrors.Errorf("exit: %w", err)
		}

		return xerrors.Errorf("plugin exec: %w", err)
	}

	return nil
}

func (p Plugin) selectPlatform() (Platform, error) {
	for _, platform := range p.Platforms {
		if platform.Selector == nil {
			return platform, nil
		}

		selector := platform.Selector
		if (selector.OS == "" || runtime.GOOS == selector.OS) &&
			(selector.Arch == "" || runtime.GOARCH == selector.Arch) {
			log.Logger.Debugf("Platform found, os: %s, arch: %s", selector.OS, selector.Arch)
			return platform, nil
		}
	}
	return Platform{}, xerrors.New("platform not found")
}

func (p Plugin) install(ctx context.Context, dst, pwd string) error {
	platform, err := p.selectPlatform()
	if err != nil {
		return xerrors.Errorf("platform selection error: %w", err)
	}

	log.Logger.Debugf("Downloading the execution file from %s...", platform.URI)
	if err = download(ctx, platform.URI, dst, pwd); err != nil {
		return xerrors.Errorf("unable to download the execution file (%s): %w", platform.URI, err)
	}
	return nil
}

func Install(ctx context.Context, url string) (Plugin, error) {
	// Replace short names with full qualified names
	// e.g. kubectl => github.com/aquasecurity/trivy-plugin-kubectl
	if v, ok := officialPlugins[url]; ok {
		url = v
	}

	log.Logger.Infof("Installing the plugin from %s...", url)
	tempDir, err := os.MkdirTemp("", "trivy-plugin")
	if err != nil {
		return Plugin{}, xerrors.Errorf("failed to create a temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	pwd, err := os.Getwd()
	if err != nil {
		return Plugin{}, xerrors.Errorf("unable to get the current dir: %w", err)
	}

	if err = download(ctx, url, tempDir, pwd); err != nil {
		return Plugin{}, xerrors.Errorf("download error: %w", err)
	}

	log.Logger.Info("Loading the plugin metadata...")
	plugin, err := loadMetadata(tempDir)
	if err != nil {
		return Plugin{}, xerrors.Errorf("failed to load the plugin metadata: %w", err)
	}

	pluginDir := filepath.Join(dir(), plugin.Name)
	if err = plugin.install(ctx, pluginDir, tempDir); err != nil {
		return Plugin{}, xerrors.Errorf("failed to install the plugin: %w", err)
	}

	// Copy plugin.yaml into the plugin dir
	if _, err = utils.CopyFile(filepath.Join(tempDir, configFile), filepath.Join(pluginDir, configFile)); err != nil {
		return Plugin{}, xerrors.Errorf("failed to copy plugin.yaml: %w", err)
	}

	return plugin, nil
}

func download(ctx context.Context, src, dst, pwd string) error {
	// go-getter doesn't allow the dst directory already exists if the src is directory.
	_ = os.RemoveAll(dst)

	var opts []getter.ClientOption

	// Overwrite the file getter so that a file will be copied
	getter.Getters["file"] = &getter.FileGetter{Copy: true}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
		Options: opts,
	}

	if err := client.Get(); err != nil {
		return xerrors.Errorf("failed to download: %w", err)
	}

	return nil
}

func LoadAll() ([]Plugin, error) {
	pluginsDir := dir()
	dirs, err := os.ReadDir(pluginsDir)
	if err != nil {
		return nil, err
	}

	var plugins []Plugin
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		plugin, err := loadMetadata(filepath.Join(pluginsDir, d.Name()))
		if err != nil {
			log.Logger.Warnf("plugin load error: %s", err)
			continue
		}
		plugins = append(plugins, plugin)
	}
	return plugins, nil
}

func loadMetadata(dir string) (Plugin, error) {
	filePath := filepath.Join(dir, configFile)
	f, err := os.Open(filePath)
	if err != nil {
		return Plugin{}, xerrors.Errorf("file open error: %w", err)
	}

	var plugin Plugin
	if err = yaml.NewDecoder(f).Decode(&plugin); err != nil {
		return Plugin{}, xerrors.Errorf("yaml decode error: %w", err)
	}

	return plugin, nil
}

func dir() string {
	dataHome := os.Getenv(xdgDataHome)
	if dataHome != "" {
		return filepath.Join(dataHome, pluginsRelativeDir)
	}

	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, pluginsRelativeDir)
}
