package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cloud/auth"
)

func TestLogin(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantErr   string
		checkFile bool
	}{
		{
			name:      "valid token",
			token:     "valid-token-12345",
			checkFile: true,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: "token is required",
		},
		{
			name:    "short token",
			token:   "short",
			wantErr: "invalid token format",
		},
		{
			name:      "long valid token",
			token:     "a-very-long-and-valid-token-12345678901234567890",
			checkFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary cache directory
			cacheDir := t.TempDir()
			ctx := context.Background()

			err := auth.Login(ctx, tt.token, cacheDir)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)

			if tt.checkFile {
				// Verify config file was created
				configPath := filepath.Join(cacheDir, auth.ConfigDirName, auth.ConfigFileName)
				assert.FileExists(t, configPath)

				// Verify file permissions
				info, err := os.Stat(configPath)
				require.NoError(t, err)
				assert.Equal(t, auth.ConfigFilePermissions, info.Mode().Perm())

				// Verify token can be retrieved
				retrievedToken, err := auth.GetToken(cacheDir)
				require.NoError(t, err)
				assert.Equal(t, tt.token, retrievedToken)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name         string
		setupLogin   bool
		token        string
		expectExists bool
	}{
		{
			name:         "logout after login",
			setupLogin:   true,
			token:        "valid-token-12345",
			expectExists: false,
		},
		{
			name:         "logout without login",
			setupLogin:   false,
			expectExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			ctx := context.Background()

			// Setup: login if needed
			if tt.setupLogin {
				err := auth.Login(ctx, tt.token, cacheDir)
				require.NoError(t, err)

				// Verify login succeeded
				configPath := filepath.Join(cacheDir, auth.ConfigDirName, auth.ConfigFileName)
				assert.FileExists(t, configPath)
			}

			// Test: logout
			err := auth.Logout(ctx, cacheDir)
			require.NoError(t, err)

			// Verify config file is removed
			configPath := filepath.Join(cacheDir, auth.ConfigDirName, auth.ConfigFileName)
			if tt.expectExists {
				assert.FileExists(t, configPath)
			} else {
				_, err := os.Stat(configPath)
				assert.True(t, os.IsNotExist(err))
			}
		})
	}
}

func TestGetToken(t *testing.T) {
	tests := []struct {
		name       string
		setupLogin bool
		token      string
		wantErr    string
	}{
		{
			name:       "get token after login",
			setupLogin: true,
			token:      "valid-token-12345",
		},
		{
			name:       "get token without login",
			setupLogin: false,
			wantErr:    "not logged in",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			ctx := context.Background()

			// Setup: login if needed
			if tt.setupLogin {
				err := auth.Login(ctx, tt.token, cacheDir)
				require.NoError(t, err)
			}

			// Test: get token
			token, err := auth.GetToken(cacheDir)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.token, token)
		})
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	cacheDir := t.TempDir()
	ctx := context.Background()
	token := "test-token-12345"

	// Step 1: Login
	err := auth.Login(ctx, token, cacheDir)
	require.NoError(t, err)

	// Step 2: Verify token is stored
	retrievedToken, err := auth.GetToken(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, token, retrievedToken)

	// Step 3: Logout
	err = auth.Logout(ctx, cacheDir)
	require.NoError(t, err)

	// Step 4: Verify token is removed
	_, err = auth.GetToken(cacheDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not logged in")

	// Step 5: Login again with different token
	newToken := "new-token-67890"
	err = auth.Login(ctx, newToken, cacheDir)
	require.NoError(t, err)

	// Step 6: Verify new token is stored
	retrievedToken, err = auth.GetToken(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, newToken, retrievedToken)
}

func TestConfigFilePermissions(t *testing.T) {
	cacheDir := t.TempDir()
	ctx := context.Background()
	token := "test-token-12345"

	// Login to create config file
	err := auth.Login(ctx, token, cacheDir)
	require.NoError(t, err)

	// Check file permissions
	configPath := filepath.Join(cacheDir, auth.ConfigDirName, auth.ConfigFileName)
	info, err := os.Stat(configPath)
	require.NoError(t, err)

	// Verify permissions are 0600 (read/write for owner only)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestEmptyCacheDir(t *testing.T) {
	ctx := context.Background()

	err := auth.Login(ctx, "valid-token-12345", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache directory is required")

	err = auth.Logout(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache directory is required")

	_, err = auth.GetToken("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache directory is required")
}
