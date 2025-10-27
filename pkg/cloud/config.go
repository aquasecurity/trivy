package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

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

type Api struct {
	URL string `yaml:"url"`
}

type Scanning struct {
	Enabled         bool `yaml:"enabled"`
	UploadResults   bool `yaml:"upload-results"`
	SecretConfig    bool `yaml:"secret-config"`
	MisconfigConfig bool `yaml:"misconfig-config"`
}

type Server struct {
	URL      string   `yaml:"url"`
	Scanning Scanning `yaml:"scanning"`
}

type Config struct {
	Api        Api    `yaml:"api"`
	Server     Server `yaml:"server"`
	IsLoggedIn bool   `yaml:"-"`
	Token      string `yaml:"-"`
}

var defaultConfig = &Config{
	Api: Api{
		URL: DefaultApiUrl,
	},
	Server: Server{
		URL:      DefaultTrivyServerUrl,
		Scanning: Scanning{},
	},
}

func getConfigPath() string {
	configFileName := fmt.Sprintf("%s.yaml", ServiceName)
	return filepath.Join(fsutils.TrivyHomeDir(), configFileName)
}

func (c *Config) Save() error {
	if c.Token == "" && c.Server.URL == "" && c.Api.URL == "" {
		return xerrors.New("no config to save, required fields are token, server url, and api url")
	}

	if err := c.initFirstLogin(); err != nil {
		return err
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

// initFirstLogin initializes the default scanning settings to turn them on
// after this, the user can configure in the config using the config set/unset commands
func (c *Config) initFirstLogin() error {
	if c.Token == "" {
		// this isn't a login save, without a token it can't login
		return nil
	}

	var firstLogin bool
	_, err := keyring.Get(ServiceName, TokenKey)
	if err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
		firstLogin = true
	}

	if firstLogin {
		// if first login, turn on all scanning options
		c.Server.Scanning.Enabled = true
		c.Server.Scanning.UploadResults = true
		c.Server.Scanning.MisconfigConfig = true
		c.Server.Scanning.SecretConfig = true
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
		defaultCopy := *defaultConfig
		return &defaultCopy, nil
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
		config.Token = ""
		return &config, nil
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

	if c.Server.URL == "" {
		return xerrors.New("no server URL provided for verification")
	}

	logger := log.WithPrefix(log.PrefixCloud)

	client := xhttp.Client()
	url, err := url.JoinPath(c.Server.URL, "verify")
	if err != nil {
		return xerrors.Errorf("failed to join server URL and verify path: %w", err)
	}

	logger.Debug("Verifying Trivy Cloud token against server", log.String("verification_url", url))
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

// ListConfig shows the Trivy Cloud config in human readable format
func ListConfig() error {
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
	fmt.Printf("Filepath:  %s\n", getConfigPath())
	fmt.Printf("Logged In: %s\n", lo.Ternary(loggedIn, "Yes", "No"))
	fmt.Println()

	fields := collectConfigFields(reflect.ValueOf(cloudConfig).Elem(), "")
	maxKeyLen := 0
	for _, field := range fields {
		maxKeyLen = max(maxKeyLen, len(field.path))
	}

	for _, field := range fields {
		fmt.Printf("%-*s  %s\n", maxKeyLen, field.path, formatValue(field.value))
	}

	fmt.Println()

	return nil
}

type configField struct {
	path  string
	value reflect.Value
}

func collectConfigFields(v reflect.Value, prefix string) []configField {
	var fields []configField
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		yamlTag := field.Tag.Get("yaml")
		if yamlTag == "-" || yamlTag == "" {
			continue
		}

		tagName := strings.Split(yamlTag, ",")[0]
		fullPath := tagName
		if prefix != "" {
			fullPath = prefix + "." + tagName
		}
		if fieldValue.Kind() == reflect.Struct {
			fields = append(fields, collectConfigFields(fieldValue, fullPath)...)
		} else {
			fields = append(fields, configField{
				path:  fullPath,
				value: fieldValue,
			})
		}
	}

	return fields
}

func formatValue(v reflect.Value) string {
	switch v.Kind() {
	case reflect.Bool:
		return lo.Ternary(v.Bool(), "Enabled", "Disabled")
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%f", v.Float())
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}
