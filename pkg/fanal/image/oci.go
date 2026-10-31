package image

import (
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/xerrors"
)

func tryOCI(fileName string) (v1.Image, error) {
	inputFileName, inputRef := splitOCIRef(fileName)

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
	return getOCIImage(m, index, inputRef)
}

func getOCIImage(m *v1.IndexManifest, index v1.ImageIndex, inputRef string) (v1.Image, error) {
	for _, manifest := range m.Manifests {
		annotation := manifest.Annotations
		tag := annotation[ispec.AnnotationRefName]
		if inputRef == "" || // always select the first digest
			tag == inputRef ||
			manifest.Digest.String() == inputRef {
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

	return nil, xerrors.New("invalid OCI image ref")
}

// splitOCIRef splits an optional tag or digest off an OCI layout path,
// e.g. /path/to/oci:0.0.1 or /path/to/oci@sha256:...
//
// The path itself may contain '@' or ':' (Jenkins names workspaces "job@2" and "job@tmp"),
// so a separator splits the input only where the part before it is an OCI layout.
// When no split point is a layout, the first '@', else the first ':', is used as before.
func splitOCIRef(fileName string) (string, string) {
	if isOCILayout(fileName) {
		return fileName, ""
	}
	for _, sep := range []string{"@", ":"} {
		for i := 0; i < len(fileName); {
			j := strings.Index(fileName[i:], sep)
			if j < 0 {
				break
			}
			i += j
			if isOCILayout(fileName[:i]) {
				return fileName[:i], fileName[i+1:]
			}
			i++
		}
	}
	for _, sep := range []string{"@", ":"} {
		if path, ref, found := strings.Cut(fileName, sep); found {
			return path, ref
		}
	}
	return fileName, ""
}

func isOCILayout(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "index.json"))
	return err == nil && !fi.IsDir()
}
