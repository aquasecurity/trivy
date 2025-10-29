package image

import (
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	gzutil "github.com/aquasecurity/trivy/pkg/fanal/utils/gzip"
)

type dockerArchive struct {
	v1.Image
	repoTags []string
}

func tryDockerArchive(fileName string) (v1.Image, error) {
	opener := fileOpener(fileName)

	// Load the image
	img, err := tarball.Image(opener, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s as a Docker image: %w", fileName, err)
	}

	// Load the manifest to get RepoTags
	manifest, err := tarball.LoadManifest(opener)
	if err != nil {
		return nil, xerrors.Errorf("unable to load manifest from %s: %w", fileName, err)
	}

	return dockerArchive{
		Image:    img,
		repoTags: lo.FirstOrEmpty(manifest).RepoTags, // Take RepoTags from the first manifest entry
	}, nil
}

func fileOpener(fileName string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return gzutil.OpenFile(fileName)
	}
}
