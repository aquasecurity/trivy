package mix

import (
	"bufio"
	"strings"
	"unicode"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// Parser is a parser for mix.lock
type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("mix"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var pkgs []ftypes.Package
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
				p.logger.Warn("Cannot parse dependency", log.String("line", line))
			} else {
				p.logger.Debug("Skip git dependencies", log.String("name", name))
			}
			continue
		}
		version := strings.Trim(ss[2], `"`)
		pkgs = append(pkgs, ftypes.Package{
			ID:      dependency.ID(ftypes.Hex, name, version),
			Name:    name,
			Version: version,
			Locations: []ftypes.Location{
				{
					StartLine: lineNumber,
					EndLine:   lineNumber,
				},
			},
		})

	}
	return utils.UniquePackages(pkgs), nil, nil
}
