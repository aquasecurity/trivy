package image

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/xerrors"
)

func tryOCI(fileName string) (v1.Image, error) {
	var inputTag, inputFileName string

	// Check if tag is specified in input
	// e.g. /path/to/oci:0.0.1
	if strings.Contains(fileName, ":") {
		splitFileName := strings.SplitN(fileName, ":", 2)
		inputFileName = splitFileName[0]
		inputTag = splitFileName[1]
	} else {
		inputFileName = fileName
		inputTag = ""
	}

	lp, err := layout.FromPath(inputFileName)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s as an OCI Image: %w", fileName, err)
	}

	index, err := lp.ImageIndex()
	if err != nil {
		return nil, xerrors.Errorf("unable to retrieve index.json: %w", err)
	}

	m, err := index.IndexManifest()
	if err != nil {
		return nil, xerrors.Errorf("invalid index.json: %w", err)
	}

	if len(m.Manifests) == 0 {
		return nil, xerrors.New("no valid manifest")
	}

	// Support image having tag separated by : , otherwise support first image
	return getOCIImage(m, index, inputTag)
}

func getOCIImage(m *v1.IndexManifest, index v1.ImageIndex, inputTag string) (v1.Image, error) {
	for _, manifest := range m.Manifests {
		annotation := manifest.Annotations
		tag := annotation[ispec.AnnotationRefName]
		if inputTag == "" || // always select the first digest
			tag == inputTag {
			h := manifest.Digest
			if manifest.MediaType.IsIndex() {
				childIndex, err := index.ImageIndex(h)
				if err != nil {
					return nil, xerrors.Errorf("unable to retrieve a child image %q: %w", h.String(), err)
				}
				childManifest, err := childIndex.IndexManifest()
				if err != nil {
					return nil, xerrors.Errorf("invalid a child manifest for %q: %w", h.String(), err)
				}
				return getOCIImage(childManifest, childIndex, "")
			}

			img, err := index.Image(h)
			if err != nil {
				return nil, xerrors.Errorf("invalid OCI image: %w", err)
			}

			return img, nil
		}
	}

	return nil, xerrors.New("invalid OCI image tag")
}
