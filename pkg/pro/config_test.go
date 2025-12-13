package pro

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestGetConfigs_Secrets(t *testing.T) {

	mockServer := &mockApiServer{}
	mockServer.Start()
	defer mockServer.Close()

	tests := []struct {
		name          string
		accessToken   string
		serverURL     string
		errorContains string
	}{
		{
			name:          "incorrect api token",
			accessToken:   "invalid-token",
			serverURL:     mockServer.server.URL,
			errorContains: "failed to get secret config",
		},
		{
			name:          "config doesn't exist",
			accessToken:   "valid-token",
			serverURL:     mockServer.server.URL + "/nonexistent",
			errorContains: "failed to get secret config",
		},
		{
			name:        "simple config that exists",
			accessToken: "valid-token",
			serverURL:   mockServer.server.URL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)

			opts := &flag.Options{
				ProOptions: flag.ProOptions{
					SecretConfig:   true,
					TrivyServerURL: tt.serverURL,
				},
				ScanOptions: flag.ScanOptions{
					Scanners: types.Scanners{types.SecretScanner},
				},
			}

			err := GetConfigs(context.Background(), opts, tt.accessToken)

			if tt.errorContains != "" {
				require.ErrorContains(t, err, tt.errorContains)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, opts.SecretOptions.SecretConfigPath)
			assert.FileExists(t, opts.SecretOptions.SecretConfigPath)
		})
	}
}
