package yarn

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

var (
	yarnPatternRegexp    = regexp.MustCompile(`^\s?\\?"?(?P<package>\S+?)@(?:(?P<protocol>\S+?):)?(?P<version>.+?)\\?"?:?$`)
	yarnVersionRegexp    = regexp.MustCompile(`^"?version:?"?\s+"?(?P<version>[^"]+)"?`)
	yarnDependencyRegexp = regexp.MustCompile(`\s{4,}"?(?P<package>.+?)"?:?\s"?(?P<version>[^"]+)"?`)
)

type LockFile struct {
	Dependencies map[string]Dependency
}

type Library struct {
	Patterns []string
	Name     string
	Version  string
	Location types.Location
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

func parsePattern(target string) (packagename, protocol, version string, err error) {
	capture := yarnPatternRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", "", xerrors.New("not package format")
	}
	for i, group := range yarnPatternRegexp.SubexpNames() {
		switch group {
		case "package":
			packagename = capture[i]
		case "protocol":
			protocol = capture[i]
		case "version":
			version = capture[i]
		}
	}
	return
}

func parsePackagePatterns(target string) (packagename, protocol string, patterns []string, err error) {
	patternsSplit := strings.Split(target, ", ")
	packagename, protocol, _, err = parsePattern(patternsSplit[0])
	if err != nil {
		return "", "", nil, err
	}
	patterns = lo.Map(patternsSplit, func(pattern string, _ int) string {
		_, _, version, _ := parsePattern(pattern)
		return utils.PackageID(packagename, version)
	})
	return
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", xerrors.New("failed to parse version")
	}
	return capture[len(capture)-1], nil
}

func getDependency(target string) (name, version string, err error) {
	capture := yarnDependencyRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", xerrors.New("not dependency")
	}
	return capture[1], capture[2], nil
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
	case "workspace", "patch":
		return true
	}
	return false
}

func parseResults(patternIDs map[string]string, dependsOn map[string][]string) (deps []types.Dependency) {
	// find dependencies by patterns
	for libID, depPatterns := range dependsOn {
		depIDs := lo.Map(depPatterns, func(pattern string, index int) string {
			return patternIDs[pattern]
		})
		deps = append(deps, types.Dependency{
			ID:        libID,
			DependsOn: depIDs,
		})
	}
	return deps
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func scanBlocks(data []byte, atEOF bool) (advance int, token []byte, err error) {
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

func parseBlock(block []byte, lineNum int) (lib Library, deps []string, newLine int, err error) {
	var (
		emptyLines int // lib can start with empty lines first
		skipBlock  bool
	)

	scanner := NewLineScanner(bytes.NewReader(block))
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 {
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
					return Library{}, nil, -1,  xerrors.Errorf("failed to parse package patterns")
				}
				continue
			} else {
				lib.Patterns = patterns
				lib.Name = name
				continue
			}
		}
	}

	lib.Location = types.Location{
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
		if dep, err := parseDependency(line); err != nil {
			// finished dependencies block
			return deps
		} else {
			deps = append(deps, dep)
		}
	}

	return
}

func parseDependency(line string) (string, error) {
	if name, version, err := getDependency(line); err != nil {
		return "", err
	} else {
		return utils.PackageID(name, version), nil
	}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	lineNumber := 1
	var libs []types.Library

	// patternIDs holds mapping between patterns and library IDs
	// e.g. ajv@^6.5.5 => ajv@6.10.0
	patternIDs := map[string]string{}

	scanner := bufio.NewScanner(r)
	scanner.Split(scanBlocks)
	dependsOn := map[string][]string{}
	for scanner.Scan() {
		block := scanner.Bytes()
		lib, deps, newLine, err := parseBlock(block, lineNumber)
		lineNumber = newLine + 2
		if err != nil {
			return nil, nil, err
		} else if lib.Name == "" {
			continue
		}

		libID := utils.PackageID(lib.Name, lib.Version)
		libs = append(libs, types.Library{
			ID:        libID,
			Name:      lib.Name,
			Version:   lib.Version,
			Locations: []types.Location{lib.Location},
		})

		for _, pattern := range lib.Patterns {
			// e.g.
			//   combined-stream@^1.0.6 => combined-stream@1.0.8
			//   combined-stream@~1.0.6 => combined-stream@1.0.8
			patternIDs[pattern] = libID
			if len(deps) > 0 {
				dependsOn[libID] = deps
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("failed to scan yarn.lock, got scanner error: %s", err.Error())
	}

	// Replace dependency patterns with library IDs
	// e.g. ajv@^6.5.5 => ajv@6.10.0
	deps := parseResults(patternIDs, dependsOn)
	return libs, deps, nil
}
