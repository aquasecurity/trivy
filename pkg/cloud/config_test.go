package cloud

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestSave(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "empty config",
			config:  &Config{},
			wantErr: true,
		},
		{
			name: "config with all fields",
			config: &Config{
				Token:     "test-token-123",
				ServerURL: "https://example.com",
				ApiURL:    "https://api.example.com",
			},
			wantErr: false,
		},
		{
			name: "config without token",
			config: &Config{
				ServerURL: "https://example.com",
				ApiURL:    "https://api.example.com",
			},
			wantErr: false,
		},
	}
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			err := tt.config.Save()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			config, err := Load()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.config, config)

			configPath := getConfigPath()
			if tt.config.ServerURL != "" || tt.config.ApiURL != "" {
				assert.FileExists(t, configPath)
			}
		})
	}
}

func TestClear(t *testing.T) {
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

	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			if tt.createConfig {
				config := &Config{
					Token:     "testtoken",
					ServerURL: "https://example.com",
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
			configPath := getConfigPath()
			assert.NoFileExists(t, configPath)
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name          string
		createConfig  bool
		expectDefault bool
	}{
		{
			name:          "success when there is config to load",
			createConfig:  true,
			expectDefault: false,
		},
		{
			name:          "error when there is no config to load",
			expectDefault: true,
		},
	}

	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			token := "testtoken"
			if tt.createConfig {
				config := &Config{
					Token:     token,
					ServerURL: "https://example.com",
					ApiURL:    "https://api.example.com",
				}
				err := config.Save()
				require.NoError(t, err)
			}

			config, err := Load()
			if tt.expectDefault {
				assert.Equal(t, defaultConfig, config)
				return
			}
			require.NotNil(t, config)
			require.NoError(t, err)
			assert.Equal(t, token, config.Token)
			assert.Equal(t, "https://example.com", config.ServerURL)
			assert.Equal(t, "https://api.example.com", config.ApiURL)
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		status  int
		wantErr bool
	}{
		{
			name:    "success with valid config",
			config:  &Config{Token: "testtoken", ServerURL: "https://example.com", ApiURL: "https://api.example.com"},
			status:  http.StatusOK,
			wantErr: false,
		},
		{
			name:    "error with invalid config",
			config:  &Config{},
			status:  http.StatusUnauthorized,
			wantErr: true,
		},
	}
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/verify", r.URL.Path)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			tt.config.ServerURL = server.URL

			err := tt.config.Verify(context.Background())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestShowConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		wantErr      string
		wantContains []string
	}{
		{
			name:   "success with valid config",
			config: &Config{Token: "testtoken", ServerURL: "https://example.com", ApiURL: "https://api.example.com"},
			wantContains: []string{
				"Trivy Cloud Configuration",
				"Trivy Server URL: https://example.com",
				"API URL:          https://api.example.com",
				"Logged In:        No",
			},
		},
	}

	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			if tt.config != nil {
				err := tt.config.Save()
				require.NoError(t, err)
			}

			r, w, err := os.Pipe()
			require.NoError(t, err)

			originalStdout := os.Stdout
			os.Stdout = w

			errChan := make(chan error, 1)
			go func() {
				errChan <- ShowConfig()
				w.Close()
			}()

			output, _ := io.ReadAll(r)
			os.Stdout = originalStdout

			err = <-errChan
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			outputStr := string(output)
			for _, want := range tt.wantContains {
				assert.Contains(t, outputStr, want)
			}
		})
	}
}
