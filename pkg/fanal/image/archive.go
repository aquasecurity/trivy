package image

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/hashicorp/go-multierror"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func NewArchiveImage(fileName string) (types.Image, error) {
	img, err := newImage(fileName)
	if err != nil {
		return nil, err
	}
	return archiveImage{
		name:  fileName,
		Image: img,
	}, nil
}

func newImage(fileName string) (v1.Image, error) {
	var errs error

	// Docker archive
	img, err := tryDockerArchive(fileName)
	if err == nil {
		// Return v1.Image if the file can be opened as Docker archive
		return img, nil
	}
	errs = multierror.Append(errs, err)

	// OCI layout
	img, err = tryOCI(fileName)
	if err == nil {
		// Return v1.Image if the directory can be opened as OCI Image Format
		return img, nil
	}
	errs = multierror.Append(errs, err)

	return nil, errs
}

type archiveImage struct {
	v1.Image
	name string
}

func (img archiveImage) Name() string {
	return img.name
}

func (img archiveImage) ID() (string, error) {
	return ID(img)
}

// RepoTags returns the repository tags stored in the Docker archive's manifest.json
// For OCI layouts, this returns nil as the ref.name annotation is unreliable.
func (img archiveImage) RepoTags() []string {
	// Check if the underlying image is a Docker archive
	if da, ok := img.Image.(dockerArchive); ok {
		return da.repoTags
	}
	// For OCI layout, return nil as org.opencontainers.image.ref.name is unreliable
	return nil
}

// RepoDigests returns nil as both Docker and OCI archives do not contain RepoDigests.
// RepoDigests are registry-specific metadata representing the manifest digest as stored in a registry.
// Archives only export image content and RepoTags, not RepoDigests.
// Note: While digest information may exist in OCI index.json annotations,
// these annotations are tool-specific and cannot be reliably used as RepoDigests.
func (archiveImage) RepoDigests() []string {
	return nil
}
