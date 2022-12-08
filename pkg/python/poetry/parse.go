package poetry

import (
	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type Lockfile struct {
	Packages []struct {
		Category       string `toml:"category"`
		Description    string `toml:"description"`
		Marker         string `toml:"marker,omitempty"`
		Name           string `toml:"name"`
		Optional       bool   `toml:"optional"`
		PythonVersions string `toml:"python-versions"`
		Version        string `toml:"version"`
		Dependencies   interface{}
		Metadata       interface{}
	} `toml:"package"`
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
		if pkg.Category == "dev" {
			continue
		}
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil, nil
}
