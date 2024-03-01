package bundler

import (
	"bufio"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	libs := make(map[string]types.Library)
	var dependsOn, directDeps []string
	var deps []types.Dependency
	var pkgID string

	lineNum := 1
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse dependencies
		if countLeadingSpace(line) == 4 {
			if len(dependsOn) > 0 {
				deps = append(deps, types.Dependency{
					ID:        pkgID,
					DependsOn: dependsOn,
				})
			}
			dependsOn = make([]string, 0) // re-initialize
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			if len(s) != 2 {
				continue
			}
			version := strings.Trim(s[1], "()")          // drop parentheses
			version = strings.SplitN(version, "-", 2)[0] // drop platform (e.g. 1.13.6-x86_64-linux => 1.13.6)
			name := s[0]
			pkgID = packageID(name, version)
			libs[name] = types.Library{
				ID:       pkgID,
				Name:     name,
				Version:  version,
				Indirect: true,
				Locations: []types.Location{
					{
						StartLine: lineNum,
						EndLine:   lineNum,
					},
				},
			}
		}
		// Parse dependency graph
		if countLeadingSpace(line) == 6 {
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			dependsOn = append(dependsOn, s[0]) // store name only for now
		}
		lineNum++

		// Parse direct dependencies
		if line == "DEPENDENCIES" {
			directDeps = parseDirectDeps(scanner)
		}
	}
	// append last dependency (if any)
	if len(dependsOn) > 0 {
		deps = append(deps, types.Dependency{
			ID:        pkgID,
			DependsOn: dependsOn,
		})
	}

	// Identify which are direct dependencies
	for _, d := range directDeps {
		if l, ok := libs[d]; ok {
			l.Indirect = false
			libs[d] = l
		}
	}

	for i, dep := range deps {
		dependsOn = make([]string, 0)
		for _, pkgName := range dep.DependsOn {
			if lib, ok := libs[pkgName]; ok {
				dependsOn = append(dependsOn, packageID(pkgName, lib.Version))
			}
		}
		deps[i].DependsOn = dependsOn
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}

	libSlice := maps.Values(libs)
	sort.Slice(libSlice, func(i, j int) bool {
		return libSlice[i].Name < libSlice[j].Name
	})
	return libSlice, deps, nil
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

// Parse "DEPENDENCIES"
func parseDirectDeps(scanner *bufio.Scanner) []string {
	var deps []string
	for scanner.Scan() {
		line := scanner.Text()
		if countLeadingSpace(line) != 2 {
			// Reach another section
			break
		}
		ss := strings.Fields(line)
		if len(ss) == 0 {
			continue
		}
		deps = append(deps, ss[0])
	}
	return deps
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Bundler, name, version)
}
