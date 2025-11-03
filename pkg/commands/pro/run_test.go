package pro

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

type mockCloudServer struct {
	server          *httptest.Server
	configAvailable bool
}

func (m *mockCloudServer) Start() {
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-cloud-token" && r.Header.Get("Authorization") != "Bearer test-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api-keys/access-tokens" {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token": "test-access-token"}`))
			return
		}

		if r.URL.Path == "/configs/secrets/secret-config.yaml" {
			if !m.configAvailable {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Header.Get("Authorization") != "Bearer test-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"content": {"key": "value"}}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

func (m *mockCloudServer) Close() {
	m.server.Close()
}

func TestUpdateOptsForCloudIntegration(t *testing.T) {
	mockServer := &mockCloudServer{}
	mockServer.Start()
	defer mockServer.Close()

	tests := []struct {
		name            string
		opts            *flag.Options
		configAvailable bool
		errorContains   string
	}{
		{
			name: "valid token and config to download",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ProToken:       "valid-cloud-token",
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					SecretConfig:   true,
				},
				ScanOptions: flag.ScanOptions{
					Scanners: types.Scanners{types.SecretScanner},
				},
			},
			configAvailable: true,
		},
		{
			name: "valid token but config not requested",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ProToken:       "valid-cloud-token",
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					SecretConfig:   false,
				},
				ScanOptions: flag.ScanOptions{
					Scanners: types.Scanners{types.SecretScanner},
				},
			},
			configAvailable: true,
		},
		{
			name: "valid token but config not available",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ProToken:       "valid-cloud-token",
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					SecretConfig:   false,
				},
			},
			configAvailable: false,
		},
		{
			name: "invalid token 401 status code",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ProToken:       "invalid-token",
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					SecretConfig:   false,
				},
				ScanOptions: flag.ScanOptions{
					Scanners: types.Scanners{types.SecretScanner},
				},
			},
			configAvailable: true,
			errorContains:   "failed to get access token for Trivy Pro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)
			mockServer.configAvailable = tt.configAvailable

			err := UpdateOptsForProIntegration(t.Context(), tt.opts)

			if tt.errorContains != "" {
				require.ErrorContains(t, err, tt.errorContains)
				return
			}

			require.NoError(t, err)

			if tt.opts.ProOptions.SecretConfig && tt.opts.ScanOptions.Scanners.Enabled(types.SecretScanner) {
				assert.NotEmpty(t, tt.opts.SecretOptions.SecretConfigPath)
				assert.FileExists(t, tt.opts.SecretOptions.SecretConfigPath)
			} else {
				assert.Empty(t, tt.opts.SecretOptions.SecretConfigPath)
			}
		})
	}
}
