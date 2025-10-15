package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/samber/lo"
	"github.com/zalando/go-keyring"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

const (
	ServiceName           = "trivy-cloud"
	TokenKey              = "token"
	DefaultApiUrl         = "https://api.trivy.dev"
	DefaultTrivyServerUrl = "https://scan.trivy.dev"
)

type Config struct {
	ServerURL      string `yaml:"server-url"`
	ApiURL         string `yaml:"api-url"`
	ServerScanning bool   `yaml:"server-scanning"`
	UploadResults  bool   `yaml:"results-upload"`

	IsLoggedIn bool   `yaml:"-"`
	Token      string `yaml:"-"`
}

var defaultConfig = &Config{
	ServerScanning: true,
	UploadResults:  true,
	ServerURL:      DefaultTrivyServerUrl,
	ApiURL:         DefaultApiUrl,
}

func getConfigPath() string {
	configFileName := fmt.Sprintf("%s.yaml", ServiceName)
	return filepath.Join(fsutils.TrivyHomeDir(), configFileName)
}

func (c *Config) Save() error {
	if c.Token == "" && c.ServerURL == "" && c.ApiURL == "" {
		return xerrors.New("no config to save, required fields are token, server url, and api url")
	}

	if err := keyring.Set(ServiceName, TokenKey, c.Token); err != nil {
		return err
	}

	configPath := getConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}

	configYaml, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	yamlWithFrontmatter := append([]byte("---\n"), configYaml...)
	return os.WriteFile(configPath, yamlWithFrontmatter, 0o600)
}

func Clear() error {
	if err := keyring.Delete(ServiceName, TokenKey); err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
	}

	configPath := getConfigPath()
	if err := os.Remove(configPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// Load loads the Trivy Cloud config from the config file and the keychain
// If the config file does not exist the default config is returned
func Load() (*Config, error) {
	logger := log.WithPrefix(log.PrefixCloud)
	var config Config
	configPath := getConfigPath()
	yamlData, err := os.ReadFile(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		logger.Debug("No cloud config file found")
		return defaultConfig, nil
	}
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		return nil, err
	}

	token, err := keyring.Get(ServiceName, TokenKey)
	if err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return nil, err
		}
		logger.Debug("No token found in keychain")
		return defaultConfig, nil
	}

	config.Token = token
	return &config, nil
}

// Verify verifies the Trivy Cloud token and server URL and sets the global cloud config
// if the token is valid, the IsLoggedIn field is set to true and the global loggedIn variable is set to true
func (c *Config) Verify(ctx context.Context) error {
	if c.Token == "" {
		return xerrors.New("no token provided for verification")
	}

	if c.ServerURL == "" {
		return xerrors.New("no server URL provided for verification")
	}

	logger := log.WithPrefix(log.PrefixCloud)
	logger.Debug("Verifying Trivy Cloud token")

	client := xhttp.Client()
	url, err := url.JoinPath(c.ServerURL, "verify")
	if err != nil {
		return xerrors.Errorf("failed to join server URL and verify path: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return xerrors.Errorf("failed to create verification request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	resp, err := client.Do(req)
	if err != nil {
		return xerrors.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return xerrors.Errorf("failed to verify token: received status code %d", resp.StatusCode)
	}

	logger.Debug("Trivy Cloud token verified successfully")
	return nil

}

// OpenConfigForEditing opens the Trivy Cloud config file for editing in the default editor specified in the EDITOR environment variable
func OpenConfigForEditing() error {
	configPath := getConfigPath()

	logger := log.WithPrefix(log.PrefixCloud)
	if !fsutils.FileExists(configPath) {
		logger.Debug("Trivy Cloud config file does not exist", log.String("config_path", configPath))
		defaultConfig.Save()
		configPath = getConfigPath()
	}

	editor := getEditCommand()

	cmd := exec.Command(editor, configPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ShowConfig shows the Trivy Cloud config in human readable format
func ShowConfig() error {
	cloudConfig, err := Load()
	if err != nil {
		return xerrors.Errorf("failed to load Trivy Cloud config file: %w", err)
	}

	var loggedIn bool
	if cloudConfig.Verify(context.Background()) == nil {
		loggedIn = true
	} else {
		loggedIn = false
	}

	fmt.Println()
	fmt.Println("Trivy Cloud Configuration")
	fmt.Println("-------------------------")
	fmt.Printf("Logged In:        %s\n", lo.Ternary(loggedIn, "Yes", "No"))
	fmt.Printf("Trivy Server URL: %s\n", cloudConfig.ServerURL)
	fmt.Printf("API URL:          %s\n", cloudConfig.ApiURL)
	fmt.Printf("Server Scanning:  %s\n", lo.Ternary(cloudConfig.ServerScanning, "Enabled", "Disabled"))
	fmt.Printf("Results Upload:   %s\n", lo.Ternary(cloudConfig.UploadResults, "Enabled", "Disabled"))
	fmt.Printf("Filepath:         %s\n", getConfigPath())
	return nil
}

func getEditCommand() string {
	editor := os.Getenv("EDITOR")
	if editor != "" {
		return editor
	}

	// fallback to notepad for windows or vi for macos/linux
	if runtime.GOOS == "windows" {
		return "notepad"
	}
	return "vi"

}
