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

// RepoTags returns empty as an archive doesn't support RepoTags
func (archiveImage) RepoTags() []string {
	return nil
}

// RepoDigests returns empty as an archive doesn't support RepoDigests
func (archiveImage) RepoDigests() []string {
	return nil
}
