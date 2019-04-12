package composer

import (
	"encoding/json"

	"github.com/knqyf263/trivy/pkg/types"
)

type LockFile struct {
	Packages []Package
}
type Package struct {
	Name    string
	Version string
}

func (c *Scanner) ParseLockfile() ([]types.Library, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(c.file)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, err
	}

	var libs []types.Library
	for _, pkg := range lockFile.Packages {
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil
}
