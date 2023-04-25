package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type imageSourceFunc func(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error)

var imageSourceFuncs = map[types.ImageSource]imageSourceFunc{
	types.ContainerdImageSource: tryContainerdDaemon,
	types.PodmanImageSource:     tryPodmanDaemon,
	types.DockerImageSource:     tryDockerDaemon,
	types.RemoteImageSource:     tryRemote,
}

func parseImageSources(imageSources types.ImageSources) ([]imageSourceFunc, error) {
	funcs := []imageSourceFunc{}

	for _, r := range imageSources {
		f, ok := imageSourceFuncs[r]
		if !ok {
			return nil, xerrors.Errorf("unrecoginized image source: '%s'", r)
		}
		funcs = append(funcs, f)
	}

	return funcs, nil
}

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions) (types.Image, func(), error) {
	if len(opt.ImageSources) == 0 {
		return nil, func() {}, xerrors.Errorf("no image sources supplied")
	}

	imageSources, err := parseImageSources(opt.ImageSources)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("unable to parse image source: %w", err)
	}

	var errs error
	var nameOpts []name.Option
	if opt.RegistryOptions.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	for _, tryImageSource := range imageSources {
		img, cleanup, err := tryImageSource(ctx, imageName, ref, opt)
		if err == nil {
			return img, cleanup, nil
		}
		errs = multierror.Append(errs, err)
	}

	return nil, func() {}, errs
}

func ID(img v1.Image) (string, error) {
	h, err := img.ConfigName()
	if err != nil {
		return "", xerrors.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func LayerIDs(img v1.Image) ([]string, error) {
	conf, err := img.ConfigFile()
	if err != nil {
		return nil, xerrors.Errorf("unable to get the config file: %w", err)
	}

	var layerIDs []string
	for _, d := range conf.RootFS.DiffIDs {
		layerIDs = append(layerIDs, d.String())
	}
	return layerIDs, nil
}
