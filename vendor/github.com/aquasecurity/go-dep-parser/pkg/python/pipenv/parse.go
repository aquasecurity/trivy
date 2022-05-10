package pipenv

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type lockFile struct {
	Default map[string]dependency
	Develop map[string]dependency
}
type dependency struct {
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
	for pkgName, dependency := range lockFile.Default {
		libs = append(libs, types.Library{
			Name:    pkgName,
			Version: strings.TrimLeft(dependency.Version, "=="),
		})
	}
	return libs, nil
}
