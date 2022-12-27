package mix

import (
	"bufio"
	"fmt"
	"strings"
	"unicode"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

// Parser is a parser for mix.lock
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
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
			ID:        fmt.Sprintf("%s@%s", name, version),
			Name:      name,
			Version:   version,
			Locations: []types.Location{{StartLine: lineNumber, EndLine: lineNumber}},
		})

	}
	return utils.UniqueLibraries(libs), nil, nil
}
