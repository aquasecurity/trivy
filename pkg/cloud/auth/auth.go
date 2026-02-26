package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	// ConfigDirName is the directory name for Trivy Cloud configuration
	ConfigDirName = "cloud"
	// ConfigFileName is the configuration file name
	ConfigFileName = "config.json"
	// ConfigFilePermissions is the file permission for the config file
	ConfigFilePermissions = 0600
)

// Config represents the Trivy Cloud configuration
type Config struct {
	Token string `json:"token"`
}

// Login authenticates to Trivy Cloud and stores the token securely
func Login(ctx context.Context, token string, cacheDir string) error {
	if token == "" {
		return xerrors.New("token is required")
	}

	// Validate token format (basic validation)
	if len(token) < 10 {
		return xerrors.New("invalid token format")
	}

	// In a real implementation, we would validate the token against Trivy Cloud API
	// For now, we'll just store it securely
	if err := validateToken(ctx, token); err != nil {
		return xerrors.Errorf("token validation failed: %w", err)
	}

	// Store the token
	configPath, err := getConfigPath(cacheDir)
	if err != nil {
		return xerrors.Errorf("failed to get config path: %w", err)
	}

	config := Config{
		Token: token,
	}

	if err := saveConfig(configPath, config); err != nil {
		return xerrors.Errorf("failed to save config: %w", err)
	}

	log.InfoContext(ctx, "Login succeeded", log.FilePath(configPath))
	return nil
}

// Logout removes the stored Trivy Cloud credentials
func Logout(ctx context.Context, cacheDir string) error {
	configPath, err := getConfigPath(cacheDir)
	if err != nil {
		return xerrors.Errorf("failed to get config path: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.InfoContext(ctx, "Not logged in")
		return nil
	}

	// Remove the config file
	if err := os.Remove(configPath); err != nil {
		return xerrors.Errorf("failed to remove config: %w", err)
	}

	log.InfoContext(ctx, "Logged out", log.FilePath(configPath))
	return nil
}

// GetToken retrieves the stored token
func GetToken(cacheDir string) (string, error) {
	configPath, err := getConfigPath(cacheDir)
	if err != nil {
		return "", xerrors.Errorf("failed to get config path: %w", err)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		return "", xerrors.Errorf("failed to load config: %w", err)
	}

	return config.Token, nil
}

// validateToken validates the token against Trivy Cloud API
// This is a placeholder for the actual implementation
func validateToken(_ context.Context, token string) error {
	// TODO: Implement actual token validation against Trivy Cloud API
	// For now, just check basic format
	if len(token) < 10 {
		return xerrors.New("token too short")
	}
	return nil
}

// getConfigPath returns the path to the config file
func getConfigPath(cacheDir string) (string, error) {
	if cacheDir == "" {
		return "", xerrors.New("cache directory is required")
	}

	configDir := filepath.Join(cacheDir, ConfigDirName)
	configPath := filepath.Join(configDir, ConfigFileName)

	return configPath, nil
}

// saveConfig saves the configuration to disk
func saveConfig(configPath string, config Config) error {
	// Create directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return xerrors.Errorf("failed to create config directory: %w", err)
	}

	// Marshal config to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal config: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(configPath, data, ConfigFilePermissions); err != nil {
		return xerrors.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// loadConfig loads the configuration from disk
func loadConfig(configPath string) (Config, error) {
	var config Config

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, xerrors.New("not logged in")
	}

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, xerrors.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(data, &config); err != nil {
		return config, xerrors.Errorf("failed to unmarshal config: %w", err)
	}

	// Check file permissions
	info, err := os.Stat(configPath)
	if err != nil {
		return config, xerrors.Errorf("failed to stat config file: %w", err)
	}

	// Warn if permissions are too open
	if info.Mode().Perm() != ConfigFilePermissions {
		log.Warn(fmt.Sprintf("Config file has incorrect permissions %o, should be %o", info.Mode().Perm(), ConfigFilePermissions))
	}

	return config, nil
}
