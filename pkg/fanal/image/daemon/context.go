package daemon

import (
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/config"
	cliflags "github.com/docker/cli/cli/flags"
	"golang.org/x/xerrors"
)

// resolveDockerHost resolves the Docker daemon host based on priority:
// 1. --docker-host flag (highest priority)
// 2. DOCKER_HOST environment variable (handled by NewAPIClientFromFlags)
// 3. DOCKER_CONTEXT environment variable (handled by NewAPIClientFromFlags)
// 4. Current Docker context (default, handled by NewAPIClientFromFlags)
func resolveDockerHost(hostFlag string) (string, error) {
	// --docker-host flag
	if hostFlag != "" {
		return hostFlag, nil
	}

	// For DOCKER_HOST, DOCKER_CONTEXT and current context resolution, use docker/cli
	// This approach validates context existence and returns proper errors
	opts := &cliflags.ClientOptions{}

	// Load config from DOCKER_CONFIG or default location
	configFile, err := config.Load("")
	if err != nil {
		return "", xerrors.Errorf("failed to load Docker config: %w", err)
	}

	apiClient, err := command.NewAPIClientFromFlags(opts, configFile)
	if err != nil {
		return "", xerrors.Errorf("failed to create Docker API client: %w", err)
	}
	defer apiClient.Close()

	// Get the host from the client
	return apiClient.DaemonHost(), nil
}
