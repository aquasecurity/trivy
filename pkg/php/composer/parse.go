package composer

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type lockFile struct {
	Packages []packageInfo
}
type packageInfo struct {
	Name    string
	Version string
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockFile lockFile
	decoder := json.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
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
