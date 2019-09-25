package os

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/extractor"
	"golang.org/x/xerrors"
)

// GetFileMap is test function
func GetFileMap(prefixPath string) (extractor.FileMap, error) {
	fileMap := extractor.FileMap{}
	err := filepath.Walk(
		prefixPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return xerrors.Errorf("unknown error during file walking: %w", err)
			}
			if info.IsDir() {
				return nil
			}
			read, err := os.Open(path)
			if err != nil {
				return xerrors.Errorf("can't open file %s", path)
			}
			fileBytes, err := ioutil.ReadAll(read)
			if err != nil {
				return xerrors.Errorf("can't read file %s", path)
			}
			// delete prefix (directory) name. only leave etc/xxxx
			fileMap[path[(len(prefixPath)-1):]] = fileBytes
			return nil
		},
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to walk the file tree: %w", err)
	}
	return fileMap, nil
}
