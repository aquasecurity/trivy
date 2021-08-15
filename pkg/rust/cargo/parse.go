package cargo

import (
	"io"

	"github.com/BurntSushi/toml"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type Lockfile struct {
	Packages []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Source       string   `toml:"source,omitempty"`
		Dependencies []string `toml:"dependencies,omitempty"`
	} `toml:"package"`
	Metadata interface{}
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockfile Lockfile
	if _, err := toml.DecodeReader(r, &lockfile); err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
	}

	var libs []types.Library
	for _, pkg := range lockfile.Packages {
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil
}
