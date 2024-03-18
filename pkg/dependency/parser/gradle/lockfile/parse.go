package lockfile

import (
	"bufio"
	"strings"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(r)
	var lineNum int
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") { // skip comments
			continue
		}

		// dependency format: group:artifact:version=classPaths
		dep := strings.Split(line, ":")
		if len(dep) != 3 { // skip the last line with lists of empty configurations
			continue
		}

		name := strings.Join(dep[:2], ":")
		version := strings.Split(dep[2], "=")[0] // remove classPaths
		libs = append(libs, types.Library{
			ID:      dependency.ID(ftypes.Gradle, name, version),
			Name:    name,
			Version: version,
			Locations: []types.Location{
				{
					StartLine: lineNum,
					EndLine:   lineNum,
				},
			},
			// There is no reliable way to determine direct dependencies (even using other files).
			// Therefore, we mark all dependencies as Indirect.
			// This is necessary to try to guess direct dependencies and build a dependency tree.
			Indirect: true,
		})

	}
	return utils.UniqueLibraries(libs), nil, nil
}
