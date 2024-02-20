package gradle

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

func parseBuildGradle(fsys fs.FS, dir string) map[string]struct{} {
	f, err := openBuildGradleFile(fsys, dir)
	if err != nil {
		log.Logger.Debugf("Unable to get direct dependencies: %s", err)
		return nil
	}
	scanner := bufio.NewScanner(f)
	var depBlockStarted, depExcludeBlockStarted bool
	var deps = make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Text()

		if depExcludeBlockStarted {
			if strings.TrimSpace(line) == "}" {
				depExcludeBlockStarted = false
			}
			continue
		}

		if depBlockStarted {
			if strings.HasSuffix(line, "{") {
				depExcludeBlockStarted = true
			}
			if !strings.HasPrefix(line, "}") {
				dep := parseDepLine(line)
				if dep != "" {
					deps[dep] = struct{}{}
				}
			} else {
				break
			}
		}

		if strings.HasPrefix(line, "dependencies {") {
			depBlockStarted = true

			// Dependencies as 1 line.
			// e.g. dependencies {implementation 'junit:junit:4.13'}
			if strings.HasSuffix(line, "}") {
				dep := parseDepLine(strings.TrimLeft(strings.TrimRight(line, "}"), "}"))
				if dep != "" {
					deps[dep] = struct{}{}
				}
				break
			}
		}
	}

	if len(deps) == 0 {
		log.Logger.Debug("Unable to detect direct dependencies: `Dependencies` module is empty/missing.")
		return nil
	}
	return deps
}

func openBuildGradleFile(fsys fs.FS, dir string) (io.Reader, error) {
	f, err := fsys.Open(path.Join(dir, buildGradle))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			f, err = fsys.Open(path.Join(dir, buildGradleKts))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil, xerrors.Errorf("build.gradle/build.gradle.kts file doesn't exist.")
				} else {
					return nil, xerrors.Errorf("unable to open build.gradle.kts file: %w", err)
				}
			}
		} else {
			return nil, xerrors.Errorf("unable to open build.gradle file: %w", err)
		}
	}
	return f, nil
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
