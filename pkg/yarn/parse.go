package yarn

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

var (
	yarnPackageRegexp = regexp.MustCompile(`"?(?P<package>.+?)@.+`)
	yarnVersionPrefix = `  version "`
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

func getPackageName(target string) (packagename string, err error) {
	capture := yarnPackageRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", xerrors.New("not package format")
	}

	return capture[len(capture)-1], nil
}

func Parse(r io.Reader) (libs []types.Library, err error) {
	scanner := bufio.NewScanner(r)
	unique := map[string]struct{}{}
	var lib types.Library
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 1 {
			continue
		}

		// parse version
		if strings.HasPrefix(line, yarnVersionPrefix) {
			if lib.Name == "" {
				return nil, xerrors.New("Invalid yarn.lock format")
			}
			// fetch between version prefix and last double-quote
			version := line[11:(len(line) - 1)]
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

		// packagename line start 1 char
		if line[:1] != " " && line[:1] != "#" {
			var name string
			if name, err = getPackageName(line); err != nil {
				continue
			}
			lib.Name = name
		}
	}
	return libs, nil
}
