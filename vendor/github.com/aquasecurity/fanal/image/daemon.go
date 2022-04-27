package image

import (
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/aquasecurity/fanal/types"
)

func tryDockerDaemon(imageName string, ref name.Reference) (types.Image, func(), error) {
	img, cleanup, err := daemon.DockerImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil

}

func tryPodmanDaemon(ref string) (types.Image, func(), error) {
	img, cleanup, err := daemon.PodmanImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  ref,
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

func (d daemonImage) LayerIDs() ([]string, error) {
	return LayerIDs(d)
}
