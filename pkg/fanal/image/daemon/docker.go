package daemon

import (
	"context"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/moby/moby/client"
	"golang.org/x/xerrors"

	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

// DockerImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func DockerImage(ctx context.Context, ref name.Reference, host string) (Image, func(), error) {
	cleanup := func() {}

	// Resolve Docker host based on priority: --docker-host > DOCKER_HOST > DOCKER_CONTEXT > current context
	resolvedHost, err := resolveDockerHost(host)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to resolve Docker host: %w", err)
	}

	opts := []client.Opt{
		client.FromEnv,
	}
	if resolvedHost != "" {
		opts = append(opts, client.WithHost(resolvedHost))
	}
	c, err := client.New(opts...)

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
	inspect, err := c.ImageInspect(ctx, imageID)
	if err != nil {
		imageID = ref.String() // <image_id> pattern like `5ac716b05a9c`
		inspect, err = c.ImageInspect(ctx, imageID)
		if err != nil {
			return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", imageID, err)
		}
	}

	history, err := c.ImageHistory(ctx, imageID)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to get history (%s): %w", imageID, err)
	}

	f, err := xos.CreateTemp("", "docker-export-")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(ctx, imageID, f, c.ImageSave),
		inspect: inspect.InspectResponse,
		history: configHistory(history.Items),
	}, cleanup, nil
}
