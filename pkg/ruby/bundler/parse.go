package bundler

import (
	"bufio"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"

	"golang.org/x/xerrors"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if countLeadingSpace(line) == 4 {
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			if len(s) != 2 {
				continue
			}
			version := strings.Trim(s[1], "()")          // drop parentheses
			version = strings.SplitN(version, "-", 2)[0] // drop platform (e.g. 1.13.6-x86_64-linux => 1.13.6)
			libs = append(libs, types.Library{
				Name:    s[0],
				Version: version,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}
	return libs, nil, nil
}

func countLeadingSpace(line string) int {
	i := 0
	for _, runeValue := range line {
		if runeValue == ' ' {
			i++
		} else {
			break
		}
	}
	return i
}
