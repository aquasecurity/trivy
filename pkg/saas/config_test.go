package saas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestSave(t *testing.T) {
	tests := []struct {
		name    string
		config  *CloudConfig
		wantErr bool
	}{
		{
			name:    "empty config",
			config:  &CloudConfig{},
			wantErr: true,
		},
		{
			name: "config with all fields",
			config: &CloudConfig{
				Token:     "test-token-123",
				ServerUrl: "https://example.com",
				ApiUrl:    "https://api.example.com",
			},
			wantErr: false,
		},
		{
			name: "config without token",
			config: &CloudConfig{
				ServerUrl: "https://example.com",
				ApiUrl:    "https://api.example.com",
			},
			wantErr: false,
		},
	}

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
			if tt.config.ServerUrl != "" || tt.config.ApiUrl != "" {
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
	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
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
			configPath := getConfigPath()
			assert.NoFileExists(t, configPath)
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name         string
		createConfig bool
		expectNil    bool
	}{
		{
			name:         "success when there is config to load",
			createConfig: true,
			expectNil:    false,
		},
		{
			name:      "error when there is no config to load",
			expectNil: true,
		},
	}
	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

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
			if tt.expectNil {
				require.Nil(t, config)
				return
			}
			require.NotNil(t, config)
			require.NoError(t, err)
			assert.Equal(t, token, config.Token)
			assert.Equal(t, "https://example.com", config.ServerUrl)
			assert.Equal(t, "https://api.example.com", config.ApiUrl)
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name    string
		config  *CloudConfig
		status  int
		wantErr bool
	}{
		{
			name:    "success with valid config",
			config:  &CloudConfig{Token: "testtoken", ServerUrl: "https://example.com", ApiUrl: "https://api.example.com"},
			status:  http.StatusOK,
			wantErr: false,
		},
		{
			name:    "error with invalid config",
			config:  &CloudConfig{},
			status:  http.StatusUnauthorized,
			wantErr: true,
		},
	}
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

			tt.config.ServerUrl = server.URL

			err := tt.config.Verify(context.Background())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
