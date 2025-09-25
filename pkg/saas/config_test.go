package saas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSave(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") == "true" {
		t.Skip("Skipping test in CI environment - keychain not available")
	}

	tests := []struct {
		name    string
		config  *CloudConfig
		wantErr bool
	}{
		{
			name:    "success with token only",
			config:  &CloudConfig{Token: "testtoken"},
			wantErr: false,
		},
		{
			name:    "empty config",
			config:  &CloudConfig{},
			wantErr: true,
		},
		{
			name: "config with all fields",
			config: &CloudConfig{
				Token:         "test-token-123",
				ServerUrl:     "https://example.com",
				ApiUrl:        "https://api.example.com",
				DisableUpload: true,
			},
			wantErr: false,
		},
		{
			name: "config without token",
			config: &CloudConfig{
				ServerUrl:     "https://example.com",
				ApiUrl:        "https://api.example.com",
				DisableUpload: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer Clear()
			Clear()

			err := tt.config.Save()
			require.NoError(t, err)

			config, err := Load()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.config, config)

			configPath := getConfigPath()
			if tt.config.ServerUrl != "" || tt.config.ApiUrl != "" || tt.config.DisableUpload {
				assert.FileExists(t, configPath)
			}
		})
	}
}

func TestClear(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") == "true" {
		t.Skip("Skipping test in CI environment - keychain not available")
	}

	tests := []struct {
		name         string
		createConfig bool
		wantErr      bool
	}{
		{
			name:    "success when nothing to clear",
			wantErr: false,
		},
		{
			name:         "success when there is config to clear",
			createConfig: true,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Clear()
			defer Clear()

			if tt.createConfig {
				config := &CloudConfig{
					Token:     "testtoken",
					ServerUrl: "https://example.com",
				}
				err := config.Save()
				require.NoError(t, err)

				configPath := getConfigPath()
				assert.FileExists(t, configPath)
			}

			err := Clear()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			config, err := Load()
			require.Error(t, err)
			require.Nil(t, config)

			configPath := getConfigPath()
			assert.NoFileExists(t, configPath)
		})
	}
}

func TestLoad(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") == "true" {
		t.Skip("Skipping test in CI environment - keychain not available")
	}

	tests := []struct {
		name         string
		createConfig bool
		wantErr      bool
		expectedErr  string
	}{
		{
			name:         "success when there is config to load",
			createConfig: true,
			wantErr:      false,
		},
		{
			name:        "error when there is no config to load",
			wantErr:     true,
			expectedErr: "no configuration found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			defer Clear()
			Clear()

			token := "testtoken"
			if tt.createConfig {
				config := &CloudConfig{
					Token:     token,
					ServerUrl: "https://example.com",
					ApiUrl:    "https://api.example.com",
				}
				err := config.Save()
				require.NoError(t, err)
			}

			config, err := Load()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, token, config.Token)
			assert.Equal(t, "https://example.com", config.ServerUrl)
			assert.Equal(t, "https://api.example.com", config.ApiUrl)
		})
	}
}

func TestHybridStorage(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") == "true" {
		t.Skip("Skipping test in CI environment - keychain not available")
	}

	tests := []struct {
		name                 string
		config               *CloudConfig
		expectYamlFile       bool
		yamlShouldNotContain []string
		yamlShouldContain    []string
		expectedToken        string
		expectedServerUrl    string
	}{
		{
			name: "token in keychain, config in YAML",
			config: &CloudConfig{
				Token:         "secret-token",
				ServerUrl:     "https://server.example.com",
				ApiUrl:        "https://api.example.com",
				DisableUpload: true,
			},
			expectYamlFile:       true,
			yamlShouldNotContain: []string{"secret-token"},
			yamlShouldContain:    []string{"server_url: https://server.example.com"},
			expectedToken:        "secret-token",
			expectedServerUrl:    "https://server.example.com",
		},
		{
			name:              "token only - no YAML file",
			config:            &CloudConfig{Token: "token-only"},
			expectYamlFile:    false,
			expectedToken:     "token-only",
			expectedServerUrl: "",
		},
		{
			name: "config without token - YAML only",
			config: &CloudConfig{
				ServerUrl:     "https://no-token.example.com",
				ApiUrl:        "https://api.no-token.example.com",
				DisableUpload: false,
			},
			expectYamlFile:    true,
			yamlShouldContain: []string{"server_url: https://no-token.example.com"},
			expectedToken:     "",
			expectedServerUrl: "https://no-token.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer Clear()
			Clear()

			err := tt.config.Save()
			require.NoError(t, err)

			configPath := getConfigPath()
			if tt.expectYamlFile {
				require.FileExists(t, configPath)

				yamlContent, err := os.ReadFile(configPath)
				require.NoError(t, err)

				for _, shouldNotContain := range tt.yamlShouldNotContain {
					assert.NotContains(t, string(yamlContent), shouldNotContain)
				}

				for _, shouldContain := range tt.yamlShouldContain {
					assert.Contains(t, string(yamlContent), shouldContain)
				}
			} else {
				assert.NoFileExists(t, configPath)
			}

			loadedConfig, err := Load()
			require.NoError(t, err)
			assert.Equal(t, tt.config, loadedConfig)
			assert.Equal(t, tt.expectedToken, loadedConfig.Token)
			assert.Equal(t, tt.expectedServerUrl, loadedConfig.ServerUrl)
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name            string
		token           string
		successLoggedIn bool
		expectedError   error
	}{
		{
			name:            "success when token and server URL are valid",
			token:           "secret-token",
			successLoggedIn: true,
			expectedError:   nil,
		},
		{
			name:            "error when token is empty",
			token:           "",
			successLoggedIn: false,
			expectedError:   errors.New("no token provided for verification"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/verify", r.URL.Path)
				assert.Equal(t, "Bearer "+tt.token, r.Header.Get("Authorization"))
				if tt.successLoggedIn {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			defer server.Close()

			config := &CloudConfig{
				Token:     tt.token,
				ServerUrl: server.URL,
			}

			err := config.Verify(context.Background())
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
