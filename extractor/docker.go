package extractor

import (
	"archive/tar"
	"io"
	"io/ioutil"
	"path"
)

type DockerExtractor struct{}

func (d DockerExtractor) ExtractFiles(layer io.ReadCloser, filenames []string) (FilesMap, error) {
	data := make(map[string][]byte)

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = path.Clean(filename)

		// Determine if we should extract the element
		extract := false
		for _, s := range filenames {
			if s == filename {
				extract = true
				break
			}
		}

		if !extract {
			continue
		}

		// Extract the element
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			d, _ := ioutil.ReadAll(tr)
			data[filename] = d
		}
	}

	return data, nil

}
