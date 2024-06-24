package detection

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"strings"
)

func IsHelmChartArchive(path string, file io.Reader) bool {

	if !IsArchive(path) {
		return false
	}

	var err error
	var fr = file

	if IsZip(path) {
		if fr, err = gzip.NewReader(file); err != nil {
			return false
		}
	}
	tr := tar.NewReader(fr)

	if tr == nil {
		return false
	}

	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "Chart.yaml") {
			return true
		}
	}
	return false
}

func IsArchive(path string) bool {
	return strings.HasSuffix(path, ".tar") || IsZip(path)
}

func IsZip(path string) bool {
	return strings.HasSuffix(path, ".tgz") || strings.HasSuffix(path, ".tar.gz")
}
