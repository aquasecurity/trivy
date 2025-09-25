package saas

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

const (
	ServiceName = "trivy-cloud"
	TokenKey    = "token"
)

type CloudConfig struct {
	Token         string `yaml:"-"`
	IsLoggedIn    bool   `yaml:"-"`
	ServerUrl     string `yaml:"server_url"`
	ApiUrl        string `yaml:"api_url"`
	DisableUpload bool   `yaml:"disable_upload"`
}

type configData struct {
	ServerUrl     string `yaml:"server_url"`
	ApiUrl        string `yaml:"api_url"`
	DisableUpload bool   `yaml:"disable_upload"`
}

func getConfigPath() string {
	configFileName := fmt.Sprintf("%s.yaml", ServiceName)
	return filepath.Join(fsutils.TrivyHomeDir(), configFileName)
}

func (c *CloudConfig) Save() error {
	if c.Token != "" {
		if err := keyring.Set(ServiceName, TokenKey, c.Token); err != nil {
			return err
		}
	}
	if c.ServerUrl != "" || c.ApiUrl != "" || c.DisableUpload {
		configPath := getConfigPath()

		if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
			return err
		}
		data := configData{
			ServerUrl:     c.ServerUrl,
			ApiUrl:        c.ApiUrl,
			DisableUpload: c.DisableUpload,
		}

		configYaml, err := yaml.Marshal(data)
		if err != nil {
			return err
		}

		return os.WriteFile(configPath, configYaml, 0o600)
	}

	return nil
}

func Clear() error {
	if err := keyring.Delete(ServiceName, TokenKey); err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
	}

	configPath := getConfigPath()
	if err := os.Remove(configPath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

func Load() (*CloudConfig, error) {
	logger := log.WithPrefix("trivy-cloud")
	var config CloudConfig
	var hasToken, hasConfig bool

	token, err := keyring.Get(ServiceName, TokenKey)
	if err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return nil, err
		}
		logger.Debug("No token found in keychain")
		return nil, nil
	}

	config.Token = token
	configPath := getConfigPath()
	yamlData, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		var data configData
		if err := yaml.Unmarshal(yamlData, &data); err != nil {
			return nil, err
		}

		config.ServerUrl = data.ServerUrl
		config.ApiUrl = data.ApiUrl
		config.DisableUpload = data.DisableUpload
		hasConfig = true
	}

	if !hasToken && !hasConfig {
		return nil, errors.New("no configuration found")
	}

	return &config, nil
}

// Verify verifies the SaaS token and server URL and sets the global cloud config
// if the token is valid, the IsLoggedIn field is set to true and the global loggedIn variable is set to true
func (c *CloudConfig) Verify(ctx context.Context) error {
	if c.Token == "" {
		return xerrors.New("no token provided for verification")
	}

	if c.ServerUrl == "" {
		return xerrors.New("no server URL provided for verification")
	}

	logger := log.WithPrefix("trivy-cloud")
	logger.Debug("Verifying SaaS token")

	client := xhttp.ClientWithContext(ctx)
	url := fmt.Sprintf("%s/verify", c.ServerUrl)
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
		logger.Error("Failed to verify token", log.Err(err), log.Int("status_code", resp.StatusCode))
		return xerrors.Errorf("failed to verify token: received status code %d", resp.StatusCode)
	}

	setGlobalCloudConfig(c)
	logger.Debug("SaaS token verified successfully")
	return nil

}
