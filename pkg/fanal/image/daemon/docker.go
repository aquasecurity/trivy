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
func DockerImage(ref name.Reference, host string) (Image, func(), error) {
	cleanup := func() {}

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}
	if host != "" {
		// adding host parameter to the last assuming it will pick up more preference
		opts = append(opts, client.WithHost(host))
	}
	c, err := client.NewClientWithOpts(opts...)

	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a docker client: %w", err)
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()

	// <image_name>:<tag> pattern like "alpine:3.15"
	// or
	// <image_name>@<digest> pattern like "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"
	imageID := ref.Name()
	inspect, _, err := c.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		imageID = ref.String() // <image_id> pattern like `5ac716b05a9c`
		inspect, _, err = c.ImageInspectWithRaw(context.Background(), imageID)
		if err != nil {
			return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", imageID, err)
		}
	}

	history, err := c.ImageHistory(context.Background(), imageID)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to get history (%s): %w", imageID, err)
	}

	f, err := os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(context.Background(), imageID, f, c.ImageSave),
		inspect: inspect,
		history: configHistory(history),
	}, cleanup, nil
}
