package yarn

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

var (
	yarnLocatorRegexp = regexp.MustCompile(`"?(?P<package>.+?)@(?:(?P<protocol>.+?):)?.+`)
	yarnVersionRegexp = regexp.MustCompile(`\s+"?version:?"?\s+"?(?P<version>[^"]+)"?`)
)

type LockFile struct {
	Dependencies map[string]Dependency
}
type Dependency struct {
	Version string
	// TODO : currently yarn can't recognize Dev flag.
	// That need to parse package.json for Dev flag
	Dev          bool
	Dependencies map[string]Dependency
}

func parsePackageLocator(target string) (packagename, protocol string, err error) {
	capture := yarnLocatorRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", "", xerrors.New("not package format")
	}
	for i, group := range yarnLocatorRegexp.SubexpNames() {
		switch group {
		case "package":
			packagename = capture[i]
		case "protocol":
			protocol = capture[i]
		}
	}
	return
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", xerrors.New("not version")
	}
	return capture[len(capture)-1], nil
}

func validProtocol(protocol string) (valid bool) {
	switch protocol {
	// only scan npm packages
	case "npm", "":
		return true
	}
	return false
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) (libs []types.Library, deps []types.Dependency, err error) {
	scanner := bufio.NewScanner(r)
	unique := map[string]struct{}{}
	var lib types.Library
	var skipPackage bool
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 1 {
			continue
		}

		// parse version
		var version string
		if version, err = getVersion(line); err == nil {
			if skipPackage {
				continue
			}
			if lib.Name == "" {
				return nil, nil, xerrors.New("Invalid yarn.lock format")
			}
			// fetch between version prefix and last double-quote
			symbol := fmt.Sprintf("%s@%s", lib.Name, version)
			if _, ok := unique[symbol]; ok {
				lib = types.Library{}
				continue
			}

			lib.Version = version
			libs = append(libs, lib)
			lib = types.Library{}
			unique[symbol] = struct{}{}
			continue
		}
		// skip __metadata block
		if skipPackage = strings.HasPrefix(line, "__metadata"); skipPackage {
			continue
		}
		// packagename line start 1 char
		if line[:1] != " " && line[:1] != "#" {
			var name string
			var protocol string
			if name, protocol, err = parsePackageLocator(line); err != nil {
				continue
			}
			if skipPackage = !validProtocol(protocol); skipPackage {
				continue
			}
			lib.Name = name
		}
	}
	return libs, nil, nil
}
