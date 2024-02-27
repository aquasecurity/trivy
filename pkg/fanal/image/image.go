package image

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/log"
)

type imageSourceFunc func(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error)

var rustBaseImageLayerRegex = ".*(ENV RUSTUP_HOME).*(CARGO_HOME).*(RUST_VERSION).*(RUN).*(rustArch=).*(rustup --version).*(cargo --version).*"
var golangBaseLayersRegex = ".*(ENV GOPATH).*(ENV PATH).*(/usr/local/go/bin).*(mkdir -p).*(GOPATH/src).*(WORKDIR).*"

var imageSourceFuncs = map[types.ImageSource]imageSourceFunc{
	types.ContainerdImageSource: tryContainerdDaemon,
	types.PodmanImageSource:     tryPodmanDaemon,
	types.DockerImageSource:     tryDockerDaemon,
	types.RemoteImageSource:     tryRemote,
}

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions) (types.Image, func(), error) {
	if len(opt.ImageSources) == 0 {
		return nil, func() {}, xerrors.New("no image sources supplied")
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

	for _, src := range opt.ImageSources {
		trySrc, ok := imageSourceFuncs[src]
		if !ok {
			log.Logger.Warnf("Unknown image source: '%s'", src)
			continue
		}

		img, cleanup, err := trySrc(ctx, imageName, ref, opt)
		if err == nil {
			// Return v1.Image if the image is found
			return img, cleanup, nil
		}
		err = multierror.Prefix(err, fmt.Sprintf("%s error:", src))
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
	var entrypointIndexFound bool
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

		// Hack to handle golang base images which don't have a CMD/Entrypoint instruction
		// i != len(histories)-1 : is to handle scenarios where the golang base image itself is being scanned
		/*
			Go version 1.16-latest tend to have the following instructions in the last 5 layers

			ENV GOPATH /go
			ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
			COPY --from=build --link /usr/local/go/ /usr/local/go/  ............ [not present in older versions]
			RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 1777 "$GOPATH"
			WORKDIR $GOPATH
		*/
		// We are looking for an occurence of the same
		if i != len(histories)-1 && (strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop) WORKDIR ") ||
			strings.HasPrefix(h.CreatedBy, "WORKDIR ")) {

			// check if we have a subset of 5 layers available since WORKDIR is encountered
			if (i-4) >= 0 && i+1 < len(histories) {
				golangBaseLayer := ""
				for _, cmd := range histories[i-4 : i+1] {
					golangBaseLayer = golangBaseLayer + cmd.CreatedBy + " "
				}
				if match, _ := regexp.MatchString(golangBaseLayersRegex, golangBaseLayer); match {
					baseImageIndex = i
					break
				}
			}
		}

		// Hack to handle rust base images which don't have a CMD/Entrypoint instruction
		// i != len(histories)-1 : is to handle scenarios where the rusts base image itself is being scanned
		/*
			Rust base image tend to have the following instructions in the last 2 layers

			ENV RUSTUP_HOME=/usr/local/rustup \
			CARGO_HOME=/usr/local/cargo \
			PATH=/usr/local/cargo/bin:$PATH \
			RUST_VERSION=1.76.0

			RUN set -eux; \
			    dpkgArch="$(dpkg --print-architecture)"; \
			    case "${dpkgArch##*-}" in \
			        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db' ;; \
			        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='f21c44b01678c645d8fbba1e55e4180a01ac5af2d38bcbd14aa665e0d96ed69a' ;; \
			        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800' ;; \
			        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='e7b0f47557c1afcd86939b118cbcf7fb95a5d1d917bdd355157b63ca00fc4333' ;; \
			        ppc64el) rustArch='powerpc64le-unknown-linux-gnu'; rustupSha256='1032934fb154ad2d365e02dcf770c6ecfaec6ab2987204c618c21ba841c97b44' ;; \
			        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
			    esac; \
			    url="https://static.rust-lang.org/rustup/archive/1.26.0/${rustArch}/rustup-init"; \
			    wget "$url"; \
			    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
			    chmod +x rustup-init; \
			    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
			    rm rustup-init; \
			    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
			    rustup --version; \
			    cargo --version; \
			    rustc --version;
		*/
		// We are looking for an occurence of the same
		if i != len(histories)-1 && (strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop) RUN ") ||
			strings.HasPrefix(h.CreatedBy, "RUN ") && strings.Contains(h.CreatedBy, "RUST")) {

			// check if we have a subset of 2 layers available since RUN is encountered
			if (i-1) >= 0 && i+1 < len(histories) {
				rustBaseImageLayer := ""
				for _, cmd := range histories[i-1 : i+1] {
					rustBaseImageLayer = rustBaseImageLayer + cmd.CreatedBy + " "
				}

				if match, _ := regexp.MatchString(rustBaseImageLayerRegex, rustBaseImageLayer); match {
					baseImageIndex = i
					break
				}
			}
		}

		if !h.EmptyLayer {
			continue
		}

		// Assumptions:
		// 1. Most base image have a CMD instruction
		// 2. In case  ENTRYPOINT instruction is encountered then check if next instruction is CMD. If yes, then CMD is the last base image layer, else ENTRYPOINT

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}

		// if entry point exists but command is missing  then assume entrypoint as base image index
		if entrypointIndexFound {
			break
		}

		// if entry point exsists then update entrypointIndex and baseImageIndex
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  ENTRYPOINT") ||
			strings.HasPrefix(h.CreatedBy, "ENTRYPOINT") { // BuildKit
			entrypointIndexFound = true
			baseImageIndex = i
		}
	}
	return baseImageIndex
}
