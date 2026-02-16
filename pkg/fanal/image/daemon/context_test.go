package daemon_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/context/docker"
	"github.com/docker/cli/cli/context/store"
	dockerclient "github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/image/daemon"
)

const testContextName = "test-context"

// createTestContext creates a Docker context using docker/cli context store API
func createTestContext(dockerConfigDir string) error {
	// Create context store with proper configuration
	cfg := store.NewConfig(
		func() any { return &store.Metadata{} },
		store.EndpointTypeGetter(docker.DockerEndpoint, func() any { return &docker.EndpointMeta{} }),
	)
	contextStore := store.New(dockerConfigDir, cfg)

	// Create context metadata
	contextMetadata := store.Metadata{
		Name: testContextName,
		Endpoints: map[string]any{
			docker.DockerEndpoint: docker.EndpointMeta{
				Host: testContextHost,
			},
		},
	}

	// Create or update the context
	return contextStore.CreateOrUpdate(contextMetadata)
}

// TestResolveDockerHost tests Docker host resolution with various scenarios
// It's challenging to test it through DockerImage due to the need for a Docker daemon,
// so we test the resolveDockerHost function directly, although it's private.
func TestResolveDockerHost(t *testing.T) {
	tests := []struct {
		name           string
		hostFlag       string
		hostEnv        string
		contextEnv     string
		currentContext string
		want           string
		wantErr        string
	}{
		{
			name:           "flag takes highest priority",
			hostFlag:       testFlagHost,
			hostEnv:        testEnvHost,
			contextEnv:     "",
			currentContext: "",
			want:           testFlagHost,
		},
		{
			name:           "DOCKER_HOST takes priority over context",
			hostFlag:       "",
			hostEnv:        testEnvHost,
			contextEnv:     "",
			currentContext: "",
			want:           testEnvHost,
		},
		{
			name:           "valid context is used",
			hostFlag:       "",
			hostEnv:        "",
			contextEnv:     testContextName,
			currentContext: "",
			want:           testContextHost,
		},
		{
			name:           "current context is used when no options",
			hostFlag:       "",
			hostEnv:        "",
			contextEnv:     "",
			currentContext: testContextName,
			want:           testContextHost,
		},
		{
			name:           "default context uses default socket when no options",
			hostFlag:       "",
			hostEnv:        "",
			contextEnv:     "",
			currentContext: "",
			want:           dockerclient.DefaultDockerHost,
		},
		{
			name:           "invalid context fails",
			hostFlag:       "",
			hostEnv:        "",
			contextEnv:     "non-existent-context",
			currentContext: "",
			wantErr:        "failed to create Docker API client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary Docker config directory
			testDir := t.TempDir()

			t.Setenv("DOCKER_CONFIG", testDir)
			t.Setenv("DOCKER_HOST", tt.hostEnv)
			t.Setenv("DOCKER_CONTEXT", tt.contextEnv)

			// Set the config directory for docker/cli to use
			// This is required to handle global state in docker/cli config.
			// Due to sync.Once in docker/cli, this cannot be fully cleaned up after tests.
			config.SetDir(testDir)

			// Always create a test context
			contextDir := filepath.Join(testDir, "contexts")

			err := createTestContext(contextDir)
			require.NoError(t, err)

			// Create config.json
			configData := map[string]any{
				"currentContext": tt.currentContext,
			}

			configJSON, err := json.MarshalIndent(configData, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(testDir, "config.json"), configJSON, 0o644))

			// Test resolveDockerHost
			got, err := daemon.ResolveDockerHost(tt.hostFlag)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
