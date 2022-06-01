package core_deps

import (
	"encoding/json"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"

	"github.com/aquasecurity/go-dep-parser/pkg/log"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var depsFile dotNetDependencies

	decoder := json.NewDecoder(r)

	if err := decoder.Decode(&depsFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .deps.json file: %s", err.Error())
	}

	var libraries []types.Library
	for nameVer, lib := range depsFile.Libraries {
		if !strings.EqualFold(lib.Type, "package") {
			continue
		}

		split := strings.Split(nameVer, "/")
		if len(split) != 2 {
			// Invalid name
			log.Logger.Warnf("Cannot parse .NET library version from: %s", nameVer)
			continue
		}

		libraries = append(libraries, types.Library{
			Name:    split[0],
			Version: split[1],
		})
	}

	return libraries, nil, nil
}

type dotNetDependencies struct {
	Libraries map[string]dotNetLibrary `json:"libraries"`
}

type dotNetLibrary struct {
	Type string `json:"type"`
}
