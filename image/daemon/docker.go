package daemon

import (
	"context"
	"os"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"
)

// DockerImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func DockerImage(ref name.Reference) (Image, func(), error) {
	cleanup := func() {}

	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a docker client: %w", err)
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	inspect, _, err := c.ImageInspectWithRaw(context.Background(), ref.Name())
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref.Name(), err)
	}

	history, err := c.ImageHistory(context.Background(), ref.Name())
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to get history (%s): %w", ref.Name(), err)
	}

	f, err := os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file")
	}

	cleanup = func() {
		c.Close()
		f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(ref.Name(), f, c.ImageSave),
		inspect: inspect,
		history: history,
	}, cleanup, nil
}
