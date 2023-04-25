package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type RuntimeFunc func(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error)

var runtimeFuncs = map[types.Runtime]RuntimeFunc{
	types.ContainerdRuntime: tryContainerdDaemon,
	types.PodmanRuntime:     tryPodmanDaemon,
	types.DockerRuntime:     tryDockerDaemon,
	types.RemoteRuntime:     tryRemote,
}

func parseRuntimes(runtimes types.Runtimes) ([]RuntimeFunc, error) {
	funcs := []RuntimeFunc{}

	for _, r := range runtimes {
		f, ok := runtimeFuncs[r]
		if !ok {
			return nil, xerrors.Errorf("unrecoginized runtime: '%s'", r)
		}
		funcs = append(funcs, f)
	}

	return funcs, nil
}

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions) (types.Image, func(), error) {
	if len(opt.Runtimes) == 0 {
		return nil, func() {}, xerrors.Errorf("no runtimes supplied")
	}

	runtimes, err := parseRuntimes(opt.Runtimes)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("unable to parse runtimes: %w", err)
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

	for _, tryRuntime := range runtimes {
		img, cleanup, err := tryRuntime(ctx, imageName, ref, opt)
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
