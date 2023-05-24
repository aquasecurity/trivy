package image

import (
	"context"
	"strings"

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

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions, opts ...Option) (types.Image, func(), error) {
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
	if opt.RegistryOptions.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	// Try accessing Docker Daemon
	if o.dockerd {
		img, cleanup, err := tryDockerDaemon(imageName, ref, opt.DockerOptions)
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
		img, err := tryRemote(ctx, imageName, ref, opt.RegistryOptions)
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

// GuessBaseImageIndex tries to guess index of base layer
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func GuessBaseImageIndex(histories []v1.History) int {
	baseImageIndex := -1
	var foundNonEmpty bool
	for i := len(histories) - 1; i >= 0; i-- {
		h := histories[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}
	return baseImageIndex
}
