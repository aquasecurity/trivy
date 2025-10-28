package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

type ConfigType string

const (
	// Additional config types can be added here - in future pipeline rego etc
	ConfigTypeSecret ConfigType = "secret"
)

const (
	SecretConfigPath = "/configs/secrets/secret-config.yaml"
	configCacheTTL   = time.Hour
)

var configPaths = map[ConfigType]string{
	ConfigTypeSecret: SecretConfigPath,
}

type cloudConfigResponse struct {
	Content map[string]any `json:"content"`
}

func GetConfigs(ctx context.Context, opts *flag.Options, accessToken string) error {
	logger := log.WithPrefix(log.PrefixCloud)
	client := xhttp.ClientWithContext(ctx)

	if opts.CloudOptions.SecretConfig && opts.Scanners.Enabled(types.SecretScanner) {
		if opts.SecretOptions.SecretConfigPath != "" {
			logger.Warn("Secret config path already set", log.String("configPath", opts.SecretOptions.SecretConfigPath))
			return nil
		}

		configPath, err := getConfigFromTrivyCloud(ctx, client, opts, accessToken, ConfigTypeSecret)
		if err != nil {
			return xerrors.Errorf("failed to get secret config: %w", err)
		}
		if configPath != "" {
			opts.SecretOptions.SecretConfigPath = configPath
		}
	}
	return nil
}

// getConfigFromTrivyCloud downloads a config from Trivy Cloud and saves it to a file
// it returns the path to the config file if it was downloaded successfully, otherwise it returns an error
func getConfigFromTrivyCloud(ctx context.Context, client *http.Client, opts *flag.Options, accessToken string, configType ConfigType) (string, error) {
	logger := log.WithPrefix(log.PrefixCloud)
	configTypeStr := string(configType)
	configDir := filepath.Join(fsutils.TrivyHomeDir(), "cloud", configTypeStr)
	if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
		return "", xerrors.Errorf("failed to create cloud config directory: %w", err)
	}

	configFilename := filepath.Join(configDir, "config.yaml")
	// Return cached config if it was updated within the last hour
	if stat, err := os.Stat(configFilename); err == nil && stat.ModTime().After(time.Now().Add(-configCacheTTL)) {
		logger.Debug("Config found in cache", log.String("configType", string(configType)), log.String("configPath", configFilename))
		return configFilename, nil
	}

	logger.Debug("Config not found in cache", log.String("configType", string(configType)), log.String("configPath", configFilename))
	configPath, ok := configPaths[configType]
	if !ok {
		return "", xerrors.Errorf("unknown config type: %s", configType)
	}
	configUrl, err := url.JoinPath(opts.CloudOptions.TrivyServerURL, configPath)
	if err != nil {
		return "", xerrors.Errorf("failed to join API URL and config path: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configUrl, http.NoBody)
	if err != nil {
		return "", xerrors.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return "", xerrors.Errorf("failed to get config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			logger.Debug("Config not found in Trivy Cloud", log.String("configType", string(configType)))
			return "", nil
		}
		return "", xerrors.Errorf("failed to get config: received status code %d", resp.StatusCode)
	}

	var response cloudConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", xerrors.Errorf("failed to decode config: %w", err)
	}

	if response.Content == nil {
		return "", xerrors.Errorf("config content is empty")
	}

	configContentBytes, err := yaml.Marshal(response.Content)
	if err != nil {
		return "", xerrors.Errorf("failed to marshal config content: %w", err)
	}

	if err := os.WriteFile(configFilename, configContentBytes, 0o600); err != nil {
		return "", xerrors.Errorf("failed to write config: %w", err)
	}

	return configFilename, nil
}
