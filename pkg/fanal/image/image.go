package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type options struct {
	dockerd    bool
	podman     bool
	containerd bool
	remote     bool
}

type Option func(*options)

func DisableDockerd() Option {
	return func(opts *options) {
		opts.dockerd = false
	}
}

func DisablePodman() Option {
	return func(opts *options) {
		opts.podman = false
	}
}

func DisableContainerd() Option {
	return func(opts *options) {
		opts.containerd = false
	}
}

func DisableRemote() Option {
	return func(opts *options) {
		opts.remote = false
	}
}

func NewContainerImage(ctx context.Context, imageName string, option types.DockerOption, opts ...Option) (types.Image, func(), error) {
	o := &options{
		dockerd:    true,
		podman:     true,
		containerd: true,
		remote:     true,
	}
	for _, opt := range opts {
		opt(o)
	}

	var errs error
	var nameOpts []name.Option
	if option.NonSSL {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	// Try accessing Docker Daemon
	if o.dockerd {
		img, cleanup, err := tryDockerDaemon(imageName, ref)
		if err == nil {
			// Return v1.Image if the image is found in Docker Engine
			return img, cleanup, nil
		}
		errs = multierror.Append(errs, err)
	}

	// Try accessing Podman
	if o.podman {
		img, cleanup, err := tryPodmanDaemon(imageName)
		if err == nil {
			// Return v1.Image if the image is found in Podman
			return img, cleanup, nil
		}
		errs = multierror.Append(errs, err)
	}

	// Try containerd
	if o.containerd {
		img, cleanup, err := tryContainerdDaemon(ctx, imageName)
		if err == nil {
			// Return v1.Image if the image is found in containerd
			return img, cleanup, nil
		}
		errs = multierror.Append(errs, err)
	}

	// Try accessing Docker Registry
	if o.remote {
		img, err := tryRemote(ctx, imageName, ref, option)
		if err == nil {
			// Return v1.Image if the image is found in a remote registry
			return img, func() {}, nil
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
