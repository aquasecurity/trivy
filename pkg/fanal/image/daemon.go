package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/aquasecurity/trivy/pkg/fanal/image/daemon"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func tryDockerDaemon(_ context.Context, imageName string, ref name.Reference, opt types.ImageOptions) (types.Image, func(), error) {
	img, cleanup, err := daemon.DockerImage(ref, opt.DockerOptions.Host)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil

}

func tryPodmanDaemon(_ context.Context, imageName string, _ name.Reference, _ types.ImageOptions) (types.Image, func(), error) {
	img, cleanup, err := daemon.PodmanImage(imageName)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func tryContainerdDaemon(ctx context.Context, imageName string, _ name.Reference, opts types.ImageOptions) (types.Image, func(), error) {
	img, cleanup, err := daemon.ContainerdImage(ctx, imageName, opts)
	if err != nil {
		return nil, cleanup, err
	}

	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

type daemonImage struct {
	daemon.Image
	name string
}

func (d daemonImage) Name() string {
	return d.name
}

func (d daemonImage) ID() (string, error) {
	return ID(d)
}
