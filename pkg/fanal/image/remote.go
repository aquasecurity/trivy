package image

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/remote"
)

func tryRemote(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error) {
	// This function doesn't need cleanup
	cleanup := func() {}

	desc, err := remote.Get(ctx, ref, option.RegistryOptions)
	if err != nil {
		return nil, cleanup, err
	}

	// An empty ArtifactType or an ArtifactType with a config media type indicates a
	// regular container image. Any other ArtifactType is treated as a non-image
	// artifact (e.g., Helm charts, WASM modules, or other OCI artifacts).
	if desc.ArtifactType != "" && !v1types.MediaType(desc.ArtifactType).IsConfig() {
		return nil, cleanup, xerrors.Errorf("unsupported artifact type %q for image %q", desc.ArtifactType, imageName)
	}

	img, err := desc.Image()
	if err != nil {
		return nil, cleanup, err
	}

	// Return v1.Image if the image is found in Docker Registry
	return remoteImage{
		name:       imageName,
		Image:      img,
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, cleanup, nil

}

type remoteImage struct {
	name       string
	ref        implicitReference
	descriptor *remote.Descriptor
	v1.Image
}

func (img remoteImage) Name() string {
	return img.name
}

func (img remoteImage) ID() (string, error) {
	return ID(img)
}

func (img remoteImage) RepoTags() []string {
	tag := img.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", img.ref.RepositoryName(), tag)}
}

func (img remoteImage) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", img.ref.RepositoryName(), img.descriptor.Digest.String())
	return []string{repoDigest}
}

type implicitReference struct {
	ref name.Reference
}

func (r implicitReference) TagName() string {
	if t, ok := r.ref.(name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

func (r implicitReference) RepositoryName() string {
	ctx := r.ref.Context()
	reg := ctx.RegistryStr()
	repo := ctx.RepositoryStr()

	// Default registry
	if reg != name.DefaultRegistry {
		return fmt.Sprintf("%s/%s", reg, repo)
	}

	// Trim default namespace
	// See https://docs.docker.com/docker-hub/official_repos
	return strings.TrimPrefix(repo, "library/")
}
