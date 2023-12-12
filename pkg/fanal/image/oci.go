package image

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/xerrors"
)

func tryOCI(fileName string) (v1.Image, error) {
	// Check if tag is specified in input
	// e.g. /path/to/oci:0.0.1

	inputFileName, inputRef, found := strings.Cut(fileName, "@")

	if !found {
		inputFileName, inputRef, found = strings.Cut(fileName, ":")
	}

	if !found {
		inputFileName = fileName
		inputRef = ""
	}

	// Buildx saves OCI images to a `tar` archive by default.
	// https://docs.docker.com/build/exporters/oci-docker/#synopsis
	// We need to unzip the archive before finding the `index.json` file.
	if filepath.Ext(inputFileName) == ".tar" {
		tmpDir, err := unzipOciTarToTmpDir(inputFileName)
		if err != nil {
			return nil, xerrors.Errorf("unable to unzip OCI tarball: %w", err)
		}
		inputFileName = tmpDir
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

func unzipOciTarToTmpDir(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", xerrors.Errorf("unable to open %q: %w", path, err)
	}
	tr := tar.NewReader(f)
	tmpDir, err := os.MkdirTemp("", "trivy-oci")
	if err != nil {
		return "", xerrors.Errorf("failed to create temp dir: %w", path, err)
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return "", xerrors.Errorf("failed to extract the archive: %w", err)
		}

		tmpFileName, err := sanitizeArchivePath(tmpDir, hdr.Name)
		if err != nil {
			return "", xerrors.Errorf("failed to sanitize archive file: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err = os.Mkdir(tmpFileName, 0750); err != nil {
				return "", xerrors.Errorf("failed to create dir in temp dir: %w", err)
			}
		case tar.TypeReg:
			if err = copyFileToTmpDir(tmpFileName, tr); err != nil {
				return "", xerrors.Errorf("failed to copy file to temp dir: %w", err)
			}
		}
	}
	return tmpDir, nil
}

func copyFileToTmpDir(path string, r io.Reader) error {
	f, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf("failed to create file from tarball: %w", err)
	}
	defer f.Close()
	if _, err = io.Copy(f, r); err != nil {
		return xerrors.Errorf("failed to copy file from tarball: %w", err)
	}
	return nil
}

// SanitizeArchivePath checks Zip Slip vulnerability:
// https://github.com/securego/gosec/issues/324#issuecomment-935927967
func sanitizeArchivePath(d, t string) (v string, err error) {
	v = filepath.Join(d, t)
	if strings.HasPrefix(v, filepath.Clean(d)) {
		return v, nil
	}

	return "", xerrors.Errorf("%q is tainted (G305: Zip Slip vulnerability)", t)
}
