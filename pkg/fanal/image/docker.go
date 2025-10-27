package image

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
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
		f, err := os.Open(fileName)
		if err != nil {
			return nil, xerrors.Errorf("unable to open the file: %w", err)
		}

		var r io.Reader
		br := bufio.NewReader(f)
		r = br

		if utils.IsGzip(br) {
			r, err = gzip.NewReader(br)
			if err != nil {
				_ = f.Close()
				return nil, xerrors.Errorf("failed to open gzip: %w", err)
			}
		}
		return io.NopCloser(r), nil
	}
}
