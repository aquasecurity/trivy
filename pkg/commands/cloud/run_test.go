package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/aquasecurity/trivy/pkg/cloud"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestLogout(t *testing.T) {
	tests := []struct {
		name             string
		createConfigFile bool
	}{
		{
			name:             "successful logout when the config file exists",
			createConfigFile: true,
		},
		{
			name:             "successful logout when the config file does not exist",
			createConfigFile: false,
		},
	}

	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			defer keyring.DeleteAll(cloud.ServiceName)
			defer cloud.Clear()
			cloud.Clear()

			if tt.createConfigFile {
				config := &cloud.Config{
					Server: cloud.Server{
						URL: "https://example.com",
					},
					Api: cloud.Api{
						URL: "https://api.example.com",
					},
				}
				err := config.Save()
				require.NoError(t, err)
			}

			err := Logout()
			require.NoError(t, err)
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		serverResponse int
		wantErr        string
	}{
		{
			name:           "successful login with valid token",
			token:          "valid-token-123",
			serverResponse: http.StatusOK,
		},
		{
			name:           "login fails with empty token",
			token:          "",
			serverResponse: http.StatusOK,
			wantErr:        "token is required for Trivy Cloud login",
		},
		{
			name:           "login fails with server error",
			token:          "valid-token-123",
			serverResponse: http.StatusUnauthorized,
			wantErr:        "failed to verify token: received status code 401",
		},
		{
			name:           "login fails with server internal error",
			token:          "valid-token-123",
			serverResponse: http.StatusInternalServerError,
			wantErr:        "failed to verify token: received status code 500",
		},
	}

	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(cloud.ServiceName)

			defer cloud.Clear()
			cloud.Clear()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/verify", r.URL.Path)

				if tt.token != "" {
					expectedAuth := "Bearer " + tt.token
					assert.Equal(t, expectedAuth, r.Header.Get("Authorization"))
				}

				w.WriteHeader(tt.serverResponse)
			}))
			defer server.Close()

			opts := flag.Options{
				CloudOptions: flag.CloudOptions{
					LoginCredentials: flag.CloudLoginCredentials{
						Token: tt.token,
					},
					ApiUrl:         server.URL + "/api",
					TrivyServerUrl: server.URL,
				},
			}

			ctx := context.Background()
			err := Login(ctx, opts)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			config, err := cloud.Load()
			require.NoError(t, err)
			require.Equal(t, tt.token, config.Token)
			require.Equal(t, server.URL, config.Server.URL)
			require.Equal(t, server.URL+"/api", config.Api.URL)
		})
	}
}
