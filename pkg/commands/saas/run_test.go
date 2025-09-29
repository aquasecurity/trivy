package saas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/saas"
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

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			defer keyring.DeleteAll(saas.ServiceName)
			defer saas.Clear()
			saas.Clear()

			if tt.createConfigFile {
				config := &saas.CloudConfig{
					ServerUrl: "https://example.com",
					ApiUrl:    "https://api.example.com",
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
		wantErr        bool
		errorContains  string
	}{
		{
			name:           "successful login with valid token",
			token:          "valid-token-123",
			serverResponse: http.StatusOK,
			wantErr:        false,
		},
		{
			name:           "login fails with empty token",
			token:          "",
			serverResponse: http.StatusOK,
			wantErr:        true,
			errorContains:  "token is required for SaaS login",
		},
		{
			name:           "login fails with server error",
			token:          "valid-token-123",
			serverResponse: http.StatusUnauthorized,
			wantErr:        true,
			errorContains:  "failed to verify token: received status code 401",
		},
		{
			name:           "login fails with server internal error",
			token:          "valid-token-123",
			serverResponse: http.StatusInternalServerError,
			wantErr:        true,
			errorContains:  "failed to verify token: received status code 500",
		},
	}

	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer keyring.DeleteAll(saas.ServiceName)

			defer saas.Clear()
			saas.Clear()

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
				SaasOptions: flag.SaasOptions{
					LoginCredentials: flag.SaasLoginCredentials{
						Token: tt.token,
					},
					ApiUrl:         server.URL + "/api",
					TrivyServerUrl: server.URL,
				},
			}

			ctx := context.Background()
			err := Login(ctx, opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errorContains != "" {
					require.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)

			config, err := saas.Load()
			require.NoError(t, err)
			require.Equal(t, tt.token, config.Token)
			require.Equal(t, server.URL, config.ServerUrl)
			require.Equal(t, server.URL+"/api", config.ApiUrl)
		})
	}
}
