package yarn

import (
	"bufio"
	"fmt"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
	"io"
	"regexp"
	"strings"
)

var (
	yarnPackageRegexp      = regexp.MustCompile(`(?P<package>[^\s]*)@.*`)
	yarnVersionPrefix = `  version "`
)

type LockFile struct {
	Dependencies map[string]Dependency
}
type Dependency struct {
	Version      string
	// TODO : currently yarn can't recognize Dev flag.
	// That need to parse package.json for Dev flag
	Dev          bool
	Dependencies map[string]Dependency
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
		if strings.HasPrefix(line, yarnVersionPrefix) {
			if lib.Name == "" {
				return nil, xerrors.New("Invalid yarn.lock format")
			}
			version := line[11:(len(line) -1)]
			symbol := fmt.Sprintf("%s@%s", lib.Name, version)
			if _, ok := unique[symbol]; ok {
				lib = types.Library{}
				continue
			}

			lib.Version = version
			fmt.Println(lib)
			libs = append(libs, lib)
			lib = types.Library{}
			unique[symbol] = struct{}{}
			continue
		}
		atmarkPosition := strings.Index(line, "@")
		if atmarkPosition > 0 {
			var name string
			if strings.HasPrefix(line, `"`) {
				name = line[1:atmarkPosition]
			} else {
				name = line[:atmarkPosition]
			}
			lib.Name = name
		}
	}
	fmt.Println(libs)
	return libs, nil
}
