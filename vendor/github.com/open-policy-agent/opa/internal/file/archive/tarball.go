package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
)

// MustWriteTarGz write the list of file names and content
// into a tarball.
func MustWriteTarGz(files [][2]string) *bytes.Buffer {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for _, file := range files {
		if err := WriteFile(tw, file[0], []byte(file[1])); err != nil {
			panic(err)
		}
	}
	return &buf
}

// WriteFile adds a file header with content to the given tar writer
func WriteFile(tw *tar.Writer, path string, bs []byte) error {

	hdr := &tar.Header{
		Name:     "/" + strings.TrimLeft(path, "/"),
		Mode:     0600,
		Typeflag: tar.TypeReg,
		Size:     int64(len(bs)),
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	_, err := tw.Write(bs)
	return err
}
