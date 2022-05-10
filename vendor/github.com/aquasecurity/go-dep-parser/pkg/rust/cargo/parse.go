package cargo

import (
	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
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

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockfile Lockfile
	if _, err := toml.DecodeReader(r, &lockfile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	var libs []types.Library
	for _, pkg := range lockfile.Packages {
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil, nil //TODO add actual dependencies
}
