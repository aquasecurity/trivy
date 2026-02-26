package testutil

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"

	gzutil "github.com/aquasecurity/trivy/pkg/fanal/utils/gzip"
)

type DockerClient struct {
	*client.Client
}

func NewDockerClient(t *testing.T) *DockerClient {
	cli, err := client.New(client.FromEnv)
	require.NoError(t, err)
	return &DockerClient{Client: cli}
}

// ImageLoad loads a Docker image from a tar archive file into the Docker engine.
// It automatically registers cleanup via t.Cleanup() to remove the loaded image after the test.
func (c *DockerClient) ImageLoad(t *testing.T, ctx context.Context, imageFile string) string {
	t.Helper()
	testfile, err := os.Open(imageFile)
	require.NoError(t, err)
	defer testfile.Close()

	// Load image into docker engine
	res, err := c.Client.ImageLoad(ctx, testfile, client.ImageLoadWithQuiet(true))
	require.NoError(t, err)
	defer res.Close()

	// Parse the response and extract the loaded image name
	var data struct {
		Stream string `json:"stream"`
	}
	err = json.NewDecoder(res).Decode(&data)
	require.NoError(t, err)
	loadedImage := strings.TrimPrefix(data.Stream, "Loaded image: ")
	loadedImage = strings.TrimSpace(loadedImage)
	require.NotEmpty(t, loadedImage, data.Stream)

	// Register cleanup to remove the loaded image after the test
	t.Cleanup(func() { c.ImageRemove(t, ctx, loadedImage) })

	return loadedImage
}

func (c *DockerClient) ImageRemove(t *testing.T, ctx context.Context, imageID string) {
	t.Helper()
	_, _ = c.Client.ImageRemove(ctx, imageID, client.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
}

// ImageCleanLoad performs a clean load of a Docker image from a tar archive.
// It removes any existing images with conflicting RepoTags before loading,
// ensuring the loaded image has the correct RepoTags from the archive.
// It automatically registers cleanup via t.Cleanup() to remove the loaded image after the test.
func (c *DockerClient) ImageCleanLoad(t *testing.T, ctx context.Context, archivePath string) string {
	t.Helper()

	// Extract RepoTags from archive
	opener := func() (io.ReadCloser, error) {
		return gzutil.OpenFile(archivePath)
	}

	manifest, err := tarball.LoadManifest(opener)
	require.NoError(t, err, "failed to load manifest from archive")

	// Remove existing images with the same RepoTags to avoid conflicts
	for _, m := range manifest {
		for _, tag := range m.RepoTags {
			c.ImageRemove(t, ctx, tag)
		}
	}

	// Load image
	return c.ImageLoad(t, ctx, archivePath)
}
