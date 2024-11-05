package bundler

import (
	"bufio"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	pkgs := make(map[string]ftypes.Package)
	var dependsOn, directDeps []string
	var deps []ftypes.Dependency
	var pkgID string

	lineNum := 1
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse dependencies
		if countLeadingSpace(line) == 4 {
			if len(dependsOn) > 0 {
				deps = append(deps, ftypes.Dependency{
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
			pkgs[name] = ftypes.Package{
				ID:           pkgID,
				Name:         name,
				Version:      version,
				Relationship: ftypes.RelationshipIndirect,
				Locations: []ftypes.Location{
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
		deps = append(deps, ftypes.Dependency{
			ID:        pkgID,
			DependsOn: dependsOn,
		})
	}

	// Identify which are direct dependencies
	for _, d := range directDeps {
		if l, ok := pkgs[d]; ok {
			l.Relationship = ftypes.RelationshipDirect
			pkgs[d] = l
		}
	}

	for i, dep := range deps {
		dependsOn = make([]string, 0)
		for _, pkgName := range dep.DependsOn {
			if pkg, ok := pkgs[pkgName]; ok {
				dependsOn = append(dependsOn, packageID(pkgName, pkg.Version))
			}
		}
		deps[i].DependsOn = dependsOn
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	return pkgSlice, deps, nil
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
