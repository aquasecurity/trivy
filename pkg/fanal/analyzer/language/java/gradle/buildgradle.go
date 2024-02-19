package gradle

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/log"
)

const (
	quotes = `["']?`
	text   = `[A-Za-z0-9-_.]+`
)

var pkgRegexp = regexp.MustCompile(fmt.Sprintf(`%s(?P<id>(%s:%s:%s))%s|group: ?%s(?P<group>(%s))%s|name: ?%s(?P<name>(%s))%s|version: ?%s(?P<version>(%s))%s`,
	quotes, text, text, text, quotes, quotes, text, quotes, quotes, text, quotes, quotes, text, quotes))

func parseBuildGradle(fsys fs.FS, dir string) ([]string, bool, error) {
	f, err := fsys.Open(path.Join(dir, buildGradle))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			f, err = fsys.Open(path.Join(dir, buildGradleKts))
			if errors.Is(err, fs.ErrNotExist) {
				log.Logger.Warnf("Unable to detect direct dependencies: build.gradle/build.gradle.kts file doesn't exist.")
				return nil, false, nil
			}
			return nil, false, xerrors.Errorf("unable to open build.gradle.kts file: %w", err)
		}
		return nil, false, xerrors.Errorf("unable to open build.gradle file: %w", err)
	}

	scanner := bufio.NewScanner(f)
	var depBlockStarted bool
	var deps []string
	for scanner.Scan() {
		line := scanner.Text()

		if depBlockStarted {
			if strings.HasPrefix(line, "}") {
				break
			} else {
				deps = append(deps, parseDepLine(line))
			}
		}

		if strings.HasPrefix(line, "dependencies {") {
			depBlockStarted = true
		}
	}
	return deps, true, nil
}

func parseDepLine(line string) string {
	allMatches := pkgRegexp.FindAllStringSubmatch(line, -1)
	var group, name, ver string
	for i, groupName := range pkgRegexp.SubexpNames() {
		if groupName != "" {
			for _, matches := range allMatches {
				if match := matches[i]; match != "" {
					switch groupName {
					case "group":
						group = match
					case "name":
						name = match
					case "version":
						ver = match
					case "id":
						return match
					}
				}
			}
		}
	}
	if group != "" && name != "" && ver != "" {
		return packageID(group, name, ver)
	}
	return ""
}
