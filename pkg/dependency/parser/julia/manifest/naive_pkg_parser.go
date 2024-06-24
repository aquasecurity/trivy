package julia

import (
	"bufio"
	"io"
	"strings"
)

type pkgPosition struct {
	start int
	end   int
}
type minPkg struct {
	uuid     string
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
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "["):
			if currentPkg.uuid != "" {
				currentPkg.setEndPositionIfEmpty(lineNum - 1)
				idx[currentPkg.uuid] = currentPkg.position
			}
			currentPkg = minPkg{}
			currentPkg.position.start = lineNum

		case strings.HasPrefix(strings.TrimSpace(line), "uuid ="):
			currentPkg.uuid = propertyValue(line)
		case strings.HasPrefix(strings.TrimSpace(line), "version ="):
			currentPkg.version = propertyValue(line)
		case strings.TrimSpace(line) == "":
			currentPkg.setEndPositionIfEmpty(lineNum - 1)
		}

		lineNum++
	}
	// add last item
	if currentPkg.uuid != "" {
		currentPkg.setEndPositionIfEmpty(lineNum - 1)
		idx[currentPkg.uuid] = currentPkg.position
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
