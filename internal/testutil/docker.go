package testutil

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

type DockerClient struct {
	*client.Client
}

func NewDockerClient(t *testing.T) *DockerClient {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	return &DockerClient{Client: cli}
}

func (c *DockerClient) ImageLoad(t *testing.T, ctx context.Context, imageFile string) string {
	t.Helper()
	testfile, err := os.Open(imageFile)
	require.NoError(t, err)
	defer testfile.Close()

	// Load image into docker engine
	res, err := c.Client.ImageLoad(ctx, testfile, true)
	require.NoError(t, err)
	defer res.Body.Close()

	// Parse the response and extract the loaded image name
	var data struct {
		Stream string `json:"stream"`
	}
	err = json.NewDecoder(res.Body).Decode(&data)
	require.NoError(t, err)
	loadedImage := strings.TrimPrefix(data.Stream, "Loaded image: ")
	loadedImage = strings.TrimSpace(loadedImage)
	require.NotEmpty(t, loadedImage, data.Stream)

	t.Cleanup(func() { c.ImageRemove(t, ctx, loadedImage) })

	return loadedImage
}

func (c *DockerClient) ImageRemove(t *testing.T, ctx context.Context, imageID string) {
	t.Helper()
	_, _ = c.Client.ImageRemove(ctx, imageID, image.RemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
}
