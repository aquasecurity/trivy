package lock

import (
	"encoding/json"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type LockFile struct {
	Version int
	Targets map[string]Dependencies `json:"dependencies"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Type     string
	Resolved string
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(r)

	if err := decoder.Decode(&lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode packages.lock.json: %w", err)
	}

	libs := make([]types.Library, 0)
	for _, targetContent := range lockFile.Targets {
		for packageName, packageContent := range targetContent {
			// If package type is "project", it is the actual project, and we skip it.
			if packageContent.Type == "Project" {
				continue
			}

			lib := types.Library{
				Name:    packageName,
				Version: packageContent.Resolved,
			}
			libs = append(libs, lib)
		}
	}
	return utils.UniqueLibraries(libs), nil, nil
}
