package mix

import (
	"bufio"
	"strings"
	"unicode"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// Parser is a parser for mix.lock
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(r)
	var lineNumber int // It is used to save dependency location
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		name, body, ok := strings.Cut(line, ":")
		if !ok {
			// skip 1st and last lines
			continue
		}
		name = strings.Trim(name, `"`)

		// dependency format:
		// "<depName>": {<:hex|:git>, :<depName>, "<depVersion>", "<checksum>", [:mix], [<required deps>], hexpm", "<checksum>"},
		ss := strings.FieldsFunc(body, func(r rune) bool {
			return unicode.IsSpace(r) || r == ','
		})
		if len(ss) < 8 { // In the case where <required deps> array is empty: s == 8, in other cases s > 8
			// git repository doesn't have dependency version
			// skip these dependencies
			if !strings.Contains(ss[0], ":git") {
				log.Logger.Warnf("Cannot parse dependency: %s", line)
			} else {
				log.Logger.Debugf("Skip git dependencies: %s", name)
			}
			continue
		}
		version := strings.Trim(ss[2], `"`)
		libs = append(libs, types.Library{
			ID:      dependency.ID(ftypes.Hex, name, version),
			Name:    name,
			Version: version,
			Locations: []types.Location{
				{
					StartLine: lineNumber,
					EndLine:   lineNumber,
				},
			},
		})

	}
	return utils.UniqueLibraries(libs), nil, nil
}
