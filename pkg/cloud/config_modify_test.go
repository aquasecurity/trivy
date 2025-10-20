package cloud

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestSet(t *testing.T) {
	tests := []struct {
		name          string
		configToSet   map[string]any
		expected      *Config
		expectedError string
	}{
		{
			name:          "success with valid config",
			configToSet:   map[string]any{"server.scanning.enabled": true},
			expected:      &Config{Api: Api{URL: "https://api.trivy.dev"}, Server: Server{URL: "https://scan.trivy.dev", Scanning: Scanning{Enabled: true, UploadResults: false, SecretConfig: false, MisconfigConfig: false}}, IsLoggedIn: false, Token: ""},
			expectedError: "",
		},
		{
			name:          "success with valid config using off for a boolean",
			configToSet:   map[string]any{"server.scanning.enabled": "on"},
			expected:      &Config{Api: Api{URL: "https://api.trivy.dev"}, Server: Server{URL: "https://scan.trivy.dev", Scanning: Scanning{Enabled: true, UploadResults: false, SecretConfig: false, MisconfigConfig: false}}, IsLoggedIn: false, Token: ""},
			expectedError: "",
		},
		{
			name:          "error with invalid config",
			configToSet:   map[string]any{"server.scanning.foo": false},
			expected:      &Config{Api: Api{URL: "https://api.trivy.dev"}, Server: Server{URL: "https://scan.trivy.dev", Scanning: Scanning{Enabled: false, UploadResults: false, SecretConfig: false, MisconfigConfig: false}}, IsLoggedIn: false, Token: ""},
			expectedError: "field \"foo\" not found in config",
		},
		{
			name:          "error when setting boolean with yessir",
			configToSet:   map[string]any{"server.scanning.enabled": "yessir"},
			expected:      &Config{Api: Api{URL: "https://api.trivy.dev"}, Server: Server{URL: "https://scan.trivy.dev", Scanning: Scanning{Enabled: false, UploadResults: false, SecretConfig: false, MisconfigConfig: false}}, IsLoggedIn: false, Token: ""},
			expectedError: "cannot unmarshal !!str `yessir` into bool",
		},
		{
			name:          "error when setting boolean with invalid value",
			configToSet:   map[string]any{"server.scanning.enabled": "invalid"},
			expected:      &Config{Api: Api{URL: "https://api.trivy.dev"}, Server: Server{URL: "https://scan.trivy.dev", Scanning: Scanning{Enabled: false, UploadResults: false, SecretConfig: false, MisconfigConfig: false}}, IsLoggedIn: false, Token: ""},
			expectedError: "cannot unmarshal !!str `invalid` into bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)

			keyring.MockInit()
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			for key, value := range tt.configToSet {
				err := Set(key, value)
				if tt.expectedError != "" {
					require.ErrorContains(t, err, tt.expectedError)
					return
				}
				require.NoError(t, err)
			}

			config, err := Load()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, config)
		})
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name          string
		primeToken    bool
		setupConfig   *Config
		attribute     string
		defaultValue  any
		expected      any
		expectedError string
	}{
		{
			name:          "success with default config",
			setupConfig:   nil,
			attribute:     "server.scanning.enabled",
			defaultValue:  false,
			expected:      false,
			expectedError: "",
		},
		{
			name:       "success with custom config",
			primeToken: true,
			setupConfig: &Config{
				Token: "test",
				Server: Server{
					URL: "https://example.com",
					Scanning: Scanning{
						Enabled:         false,
						UploadResults:   true,
						SecretConfig:    false,
						MisconfigConfig: true,
					},
				},
				Api: Api{URL: "https://api.example.com"},
			},
			attribute:     "server.scanning.enabled",
			defaultValue:  false,
			expected:      false,
			expectedError: "",
		},
		{
			name:          "error with invalid attribute",
			setupConfig:   nil,
			attribute:     "server.scanning.foo",
			defaultValue:  true,
			expected:      true,
			expectedError: "field \"foo\" not found in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)

			keyring.MockInit()
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			if tt.primeToken {
				// add the key so the custom config isn't overwritten
				require.NoError(t, keyring.Set(ServiceName, TokenKey, tt.setupConfig.Token))
			}

			if tt.setupConfig != nil {
				err := tt.setupConfig.Save()
				require.NoError(t, err)
			}

			value, err := GetWithDefault(tt.attribute, tt.defaultValue)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, value)
		})
	}
}

func TestUnset(t *testing.T) {
	tests := []struct {
		name          string
		primeToken    bool
		setupConfig   *Config
		attribute     string
		expectedValue any
		expectedError string
	}{
		{
			name:          "success with default config",
			setupConfig:   defaultConfig,
			attribute:     "server.scanning.enabled",
			expectedValue: false,
			expectedError: "",
		},
		{
			name: "success with custom config",
			setupConfig: &Config{
				Token: "test",
				Server: Server{
					URL: "https://example.com",
					Scanning: Scanning{
						Enabled:         false,
						UploadResults:   true,
						SecretConfig:    false,
						MisconfigConfig: true,
					},
				},
				Api: Api{URL: "https://api.example.com"},
			},
			attribute:     "server.scanning.enabled",
			expectedValue: false,
			expectedError: "",
		},
		{
			name: "success with custom url reset",
			setupConfig: &Config{
				Token: "test",
				Server: Server{
					URL: "https://example.com",
					Scanning: Scanning{
						Enabled:         false,
						UploadResults:   true,
						SecretConfig:    false,
						MisconfigConfig: true,
					},
				},
				Api: Api{URL: "https://api.custom.com"},
			},
			attribute:     "api.url",
			expectedValue: "https://api.trivy.dev",
			expectedError: "",
		},
		{
			name:          "error with invalid attribute",
			setupConfig:   defaultConfig,
			attribute:     "server.scanning.foo",
			expectedValue: true,
			expectedError: "field \"foo\" not found in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)

			keyring.MockInit()
			defer keyring.DeleteAll(ServiceName)
			defer Clear()

			if tt.primeToken {
				// prime the token so it doesn't get overwritten
				require.NoError(t, keyring.Set(ServiceName, TokenKey, tt.setupConfig.Token))
			}

			require.NoError(t, tt.setupConfig.Save())
			err := Unset(tt.attribute)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			value, err := Get(tt.attribute)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedValue, value)
		})
	}
}
