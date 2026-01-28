package yarn

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

var (
	// yarnPatternRegexp parses the top-level package pattern in yarn.lock
	// e.g., "lodash@^4.17.0" or "my-alias@npm:lodash@^4.17.0"
	yarnPatternRegexp = regexp.MustCompile(`^\s?\\?"?(?P<package>\S+?)@(?:(?P<protocol>\S+?):)?(?P<range>.+?)\\?"?:?$`)

	// yarnDescriptorRegexp parses a package descriptor (ident@range).
	// Based on yarn's DESCRIPTOR_REGEX_LOOSE from Berry:
	// https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/structUtils.ts
	// DESCRIPTOR_REGEX_LOOSE = /^(?:@([^/]+?)\/)?([^@/]+?)(?:@(.+))?$/
	yarnDescriptorRegexp = regexp.MustCompile(`^(?:@([^/]+?)/)?([^@/]+?)(?:@(.+))?$`)

	yarnVersionRegexp    = regexp.MustCompile(`^"?version:?"?\s+"?(?P<version>[^"]+)"?`)
	yarnDependencyRegexp = regexp.MustCompile(`\s{4,}"?(?P<package>.+?)"?:?\s"?(?:(?P<protocol>\S+?):)?(?P<version>[^"]+)"?`)
)

type LockFile struct {
	Dependencies map[string]Dependency
}

type Library struct {
	Patterns []string
	Name     string
	Version  string
	Location ftypes.Location
}
type Dependency struct {
	Pattern string
	Name    string
}

type LineScanner struct {
	*bufio.Scanner
	lineCount int
}

func NewLineScanner(r io.Reader) *LineScanner {
	return &LineScanner{
		Scanner: bufio.NewScanner(r),
	}
}

func (s *LineScanner) Scan() bool {
	scan := s.Scanner.Scan()
	if scan {
		s.lineCount++
	}
	return scan
}

func (s *LineScanner) LineNum(prevNum int) int {
	return prevNum + s.lineCount - 1
}

func parsePattern(target string) (pkgName, protocol, version string, err error) {
	// Step 1: Parse the top-level pattern to extract package/alias, protocol, and range
	capture := yarnPatternRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", "", xerrors.New("not package format")
	}

	var pkg, rng string
	for i, group := range yarnPatternRegexp.SubexpNames() {
		switch group {
		case "package":
			pkg = capture[i]
		case "protocol":
			protocol = capture[i]
		case "range":
			rng = capture[i]
		}
	}

	// Step 2: If protocol is "npm", check if the range is an alias (contains a package descriptor)
	// Based on yarn's alias detection:
	// https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/LegacyMigrationResolver.ts
	// "If the range is a valid descriptor we're dealing with an alias"
	if protocol == "npm" {
		if realPkg, realVersion, ok := tryParseDescriptor(rng); ok {
			return realPkg, protocol, realVersion, nil
		}
	}

	// Not an alias - use the original package name and range as version
	return pkg, protocol, rng, nil
}

// tryParseDescriptor attempts to parse a string as a package descriptor (ident@range).
// Based on yarn's tryParseDescriptor:
// https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/structUtils.ts
// Uses DESCRIPTOR_REGEX_LOOSE = /^(?:@([^/]+?)\/)?([^@/]+?)(?:@(.+))?$/
// Returns the package name and version if parsing succeeds.
// Examples:
//   - "ms@2.1.0" → ("ms", "2.1.0", true)
//   - "@types/react" → ("@types/react", "", true)
//   - "@types/react@19.0.0" → ("@types/react", "19.0.0", true)
//   - "^1.0.0" → ("", "", false) - not a valid descriptor
//   - "latest" → ("", "", false) - not a valid descriptor
func tryParseDescriptor(descriptor string) (string, string, bool) {
	capture := yarnDescriptorRegexp.FindStringSubmatch(descriptor)
	if capture == nil {
		return "", "", false
	}

	scope, pkgName, rng := capture[1], capture[2], capture[3]

	// If the "pkgName" part looks like a version constraint, it's not a valid package descriptor.
	// This distinguishes "ms@2.1.0" (alias) from "latest" or "^1.0.0" (version constraint).
	// Example: "@my/alias@npm:@types/react@19.0.0" → descriptor="@types/react@19.0.0" → pkgName="react" (valid)
	// Example: "lodash@npm:^4.17.0" → descriptor="^4.17.0" → pkgName="^4.17.0" (invalid, starts with ^)
	if looksLikeVersionConstraint(pkgName) {
		return "", "", false
	}

	// Build full package name with scope if present
	if scope != "" {
		pkgName = "@" + scope + "/" + pkgName
	}

	return pkgName, rng, true
}

// looksLikeVersionConstraint returns true if s looks like a version constraint
// rather than a valid npm package name.
// npm package names: https://docs.npmjs.com/cli/v10/configuring-npm/package-json#name
func looksLikeVersionConstraint(s string) bool {
	if len(s) == 0 {
		return true
	}
	// Version constraints start with: digits, ^, ~, >, <, =, *
	switch s[0] {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'^', '~', '>', '<', '=', '*':
		return true
	}
	// npm dist-tags (https://docs.npmjs.com/cli/v10/commands/npm-dist-tag)
	switch s {
	case "latest", "next", "canary", "beta", "alpha", "rc", "stable", "dev", "experimental":
		return true
	}
	return false
}

func parsePackagePatterns(target string) (pkgName, protocol string, patterns []string, err error) {
	patternsSplit := strings.Split(target, ", ")

	// Step 1: detect correct package name and protocol from multiple patterns
	for _, pattern := range patternsSplit {
		name, proto, _, parseErr := parsePattern(pattern)
		if parseErr != nil {
			continue
		}

		// Save the first valid package name and protocol
		if pkgName == "" {
			pkgName = name
			protocol = proto
		}

		// Alias pattern has priority — use the real package name.
		// Example: "ip@^2.0.0", "ip@npm:@rootio/ip@2.0.0-root.io.1"
		// Here "ip" is the alias, "@rootio/ip" is the real package.
		// parsePattern returns the real name for npm: protocol aliases.
		if proto == "npm" {
			pkgName = name
			protocol = proto
			break
		}
	}
	if pkgName == "" {
		return "", "", nil, xerrors.New("not package format")
	}

	// Step 2: build patterns with correct package ID.
	// Use original name from each pattern for correct dependency mapping
	patterns = lo.Map(patternsSplit, func(pattern string, _ int) string {
		name, _, version, _ := parsePattern(pattern)
		return packageID(name, version)
	})
	return pkgName, protocol, patterns, nil
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", xerrors.Errorf("failed to parse version: '%s", target)
	}
	return capture[len(capture)-1], nil
}

func getDependency(target string) (name, version string, err error) {
	capture := yarnDependencyRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", xerrors.New("not dependency")
	}
	if !validProtocol(capture[2]) {
		return "", "", nil
	}
	return capture[1], capture[3], nil
}

func validProtocol(protocol string) bool {
	switch protocol {
	// only scan npm packages
	case "npm", "":
		return true
	}
	return false
}

func ignoreProtocol(protocol string) bool {
	switch protocol {
	case "workspace", "patch", "file", "link", "portal", "github", "git", "git+ssh", "git+http", "git+https", "git+file":
		return true
	}
	return false
}

func parseResults(patternIDs map[string]string, dependsOn map[string][]string) (deps ftypes.Dependencies) {
	// find dependencies by patterns
	for pkgID, depPatterns := range dependsOn {
		depIDs := xslices.Map(depPatterns, func(pattern string) string {
			return patternIDs[pattern]
		})
		deps = append(deps, ftypes.Dependency{
			ID:        pkgID,
			DependsOn: depIDs,
		})
	}
	return deps
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("yarn"),
	}
}

func (p *Parser) scanBlocks(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		// We have a full newline-terminated line.
		return i + 2, data[0:i], nil
	} else if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return i + 4, data[0:i], nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func (p *Parser) parseBlock(block []byte, lineNum int) (lib Library, deps []string, newLine int, err error) {
	var (
		emptyLines int // lib can start with empty lines first
		skipBlock  bool
	)

	scanner := NewLineScanner(bytes.NewReader(block))
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			emptyLines++
			continue
		}

		if line[0] == '#' || skipBlock {
			continue
		}

		// Skip this block
		if strings.HasPrefix(line, "__metadata") {
			skipBlock = true
			continue
		}

		line = strings.TrimPrefix(strings.TrimSpace(line), "\"")

		switch {
		case strings.HasPrefix(line, "version"):
			if lib.Version, err = getVersion(line); err != nil {
				skipBlock = true
			}
			continue
		case strings.HasPrefix(line, "dependencies:"):
			// start dependencies block
			deps = parseDependencies(scanner)
			continue
		}

		// try parse package patterns
		if name, protocol, patterns, patternErr := parsePackagePatterns(line); patternErr == nil {
			if patterns == nil || !validProtocol(protocol) {
				skipBlock = true
				if !ignoreProtocol(protocol) {
					// we need to calculate the last line of the block in order to correctly determine the line numbers of the next blocks
					// store the error. we will handle it later
					err = xerrors.Errorf("unknown protocol: '%s', line: %s", protocol, line)
					continue
				}
				continue
			}
			lib.Patterns = patterns
			lib.Name = name
			continue
		}
	}

	// in case an unsupported protocol is detected
	// show warning and continue parsing
	if err != nil {
		p.logger.Warn("Protocol error", log.Err(err))
		return Library{}, nil, scanner.LineNum(lineNum), nil
	}

	lib.Location = ftypes.Location{
		StartLine: lineNum + emptyLines,
		EndLine:   scanner.LineNum(lineNum),
	}

	if scanErr := scanner.Err(); scanErr != nil {
		err = scanErr
	}

	return lib, deps, scanner.LineNum(lineNum), err
}

func parseDependencies(scanner *LineScanner) (deps []string) {
	for scanner.Scan() {
		line := scanner.Text()
		dep, err := parseDependency(line)
		if err != nil {
			// finished dependencies block
			return deps
		}
		deps = append(deps, dep)
	}

	return
}

func parseDependency(line string) (string, error) {
	name, version, err := getDependency(line)
	if err != nil {
		return "", err
	}
	return packageID(name, version), nil
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, map[string][]string, error) {
	lineNumber := 1
	var pkgs ftypes.Packages

	// patternIDs holds mapping between patterns and package IDs
	// e.g. ajv@^6.5.5 => ajv@6.10.0
	// This is needed to update dependencies from `DependsOn`.
	patternIDs := make(map[string]string)

	// patternIDs holds mapping between package ID and patterns
	// e.g. `@babel/helper-regex@7.4.4` => [`@babel/helper-regex@^7.0.0`, `@babel/helper-regex@^7.4.4`]
	// This is needed to compare package patterns with patterns from package.json files in `fanal` package.
	pkgIDPatterns := make(map[string][]string)

	scanner := bufio.NewScanner(r)
	scanner.Split(p.scanBlocks)
	dependsOn := make(map[string][]string)
	for scanner.Scan() {
		block := scanner.Bytes()
		lib, deps, newLine, err := p.parseBlock(block, lineNumber)
		lineNumber = newLine + 2
		if err != nil {
			return nil, nil, nil, err
		} else if lib.Name == "" {
			continue
		}

		pkgID := packageID(lib.Name, lib.Version)
		pkgs = append(pkgs, ftypes.Package{
			ID:        pkgID,
			Name:      lib.Name,
			Version:   lib.Version,
			Locations: []ftypes.Location{lib.Location},
		})

		pkgIDPatterns[pkgID] = lib.Patterns
		for _, pattern := range lib.Patterns {
			// e.g.
			//   combined-stream@^1.0.6 => combined-stream@1.0.8
			//   combined-stream@~1.0.6 => combined-stream@1.0.8
			patternIDs[pattern] = pkgID
			if len(deps) > 0 {
				dependsOn[pkgID] = deps
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to scan yarn.lock, got scanner error: %s", err.Error())
	}

	// Replace dependency patterns with package IDs
	// e.g. ajv@^6.5.5 => ajv@6.10.0
	deps := parseResults(patternIDs, dependsOn)

	sort.Sort(pkgs)
	sort.Sort(deps)
	return pkgs, deps, pkgIDPatterns, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Yarn, name, version)
}
