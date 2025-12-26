package pro

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/pro"
	"github.com/aquasecurity/trivy/pkg/pro/hooks"
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

func TestLogout(t *testing.T) {
	tests := []struct {
		name         string
		keyRingToken string
	}{
		{
			name:         "valid token in keyring",
			keyRingToken: "valid-cloud-token",
		},
		{
			name:         "no token in keyring",
			keyRingToken: "",
		},
	}
	keyring.MockInit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keyRingToken != "" {
				require.NoError(t, pro.SaveToken(t.Context(), flag.Options{ProOptions: flag.ProOptions{}}, tt.keyRingToken))
			}
			defer func() {
				require.NoError(t, pro.DeleteTokenFromKeyring())
			}()

			err := Logout()
			require.NoError(t, err)

			// Verify the token is deleted from the keyring
			payload, err := keyring.Get(pro.KeyringService, pro.KeyringAccount)
			if err != nil {
				require.ErrorIs(t, err, keyring.ErrNotFound)
			}
			require.Empty(t, payload)
		})
	}
}

func TestStatus(t *testing.T) {
	mockServer := &mockCloudServer{}
	mockServer.Start()
	defer mockServer.Close()

	tests := []struct {
		name         string
		keyRingToken string
	}{
		{
			name:         "valid token in keyring",
			keyRingToken: "valid-cloud-token",
		},
		{
			name:         "no token in keyring",
			keyRingToken: "",
		},
	}

	keyring.MockInit()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keyRingToken != "" {
				require.NoError(t, pro.SaveToken(t.Context(), flag.Options{ProOptions: flag.ProOptions{}}, tt.keyRingToken))
			}
			defer func() {
				require.NoError(t, pro.DeleteTokenFromKeyring())
			}()

			err := Status(t.Context(), flag.Options{ProOptions: flag.ProOptions{ApiURL: mockServer.server.URL}})
			require.NoError(t, err)
		})
	}
}

func TestUpdateOptsForCloudIntegration(t *testing.T) {
	mockServer := &mockCloudServer{}
	mockServer.Start()
	defer mockServer.Close()

	tests := []struct {
		name            string
		opts            *flag.Options
		keyRingToken    string
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
			name: "valid token and upload results requested",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ProToken:       "valid-cloud-token",
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					UploadResults:  true,
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
		{
			name: "no token provided but one found in keyring",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					SecretConfig:   false,
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
				},
			},
			keyRingToken:  "valid-cloud-token",
			errorContains: "",
		},
		{
			name: "no token in keyring and moves on without error",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					SecretConfig:   false,
				},
			},
			errorContains: "",
		},
		{
			name: "invalid token in keyring",
			opts: &flag.Options{
				ProOptions: flag.ProOptions{
					ApiURL:         mockServer.server.URL,
					TrivyServerURL: mockServer.server.URL,
					SecretConfig:   false,
				},
			},
			keyRingToken:  "invalid-token",
			errorContains: "failed to get access token for Trivy Pro: failed to get access token from Trivy Pro: received status code 401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keyRingToken != "" {
				// Mock the keyring to return the token from the keyring
				keyring.MockInit()
				require.NoError(t, pro.SaveToken(t.Context(), *tt.opts, tt.keyRingToken))
			}
			defer func() {
				require.NoError(t, pro.DeleteTokenFromKeyring())
			}()

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

			if tt.opts.ProOptions.UploadResults {
				require.NotEmpty(t, extension.Hooks())
				require.IsType(t, &hooks.ReportHook{}, extension.Hooks()[0])
				extension.DeregisterHook(extension.Hooks()[0].Name())
			} else {
				require.Empty(t, extension.Hooks())
			}
		})
	}
}
