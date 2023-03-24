package cargo

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type pkgPosition struct {
	start int
	end   int
}
type minPkg struct {
	name     string
	version  string
	position pkgPosition
}

func (pkg *minPkg) setEndPositionIfEmpty(n int) {
	if pkg.position.end == 0 {
		pkg.position.end = n
	}
}

type naivePkgParser struct {
	r io.Reader
}

func (parser *naivePkgParser) parse() map[string]pkgPosition {
	var currentPkg minPkg = minPkg{}
	var idx = make(map[string]pkgPosition, 0)

	scanner := bufio.NewScanner(parser.r)
	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			if currentPkg.name != "" {
				pkgId := utils.PackageID(currentPkg.name, currentPkg.version)
				currentPkg.setEndPositionIfEmpty(lineNum - 1)
				idx[pkgId] = currentPkg.position
			}
			currentPkg = minPkg{}
			currentPkg.position.start = lineNum

		} else if strings.HasPrefix(strings.TrimSpace(line), "name =") {
			currentPkg.name = propertyValue(line)
		} else if strings.HasPrefix(strings.TrimSpace(line), "version =") {
			currentPkg.version = propertyValue(line)
		} else if strings.TrimSpace(line) == "" {
			currentPkg.setEndPositionIfEmpty(lineNum - 1)
		}

		lineNum++
	}
	// add last item
	if currentPkg.name != "" {
		pkgId := fmt.Sprintf("%s@%s", currentPkg.name, currentPkg.version)
		currentPkg.setEndPositionIfEmpty(lineNum - 1)
		idx[pkgId] = currentPkg.position
	}
	return idx
}
func propertyValue(line string) string {
	parts := strings.Split(line, "=")
	if len(parts) == 2 {
		return strings.Trim(parts[1], ` "`)
	}
	return ""
}
