package pip

import (
	"bufio"
	"io"
	"strings"
	"unicode"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

const (
	commentMarker string = "#"
	endColon      string = ";"
	hashMarker    string = "--"
)

func Parse(r io.Reader) ([]types.Library, error) {
	scanner := bufio.NewScanner(r)
	var libs []types.Library
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, " ", "")
		line = strings.ReplaceAll(line, `\`, "")
		line = rStripByKey(line, commentMarker)
		line = rStripByKey(line, endColon)
		line = rStripByKey(line, hashMarker)
		s := strings.Split(line, "==")
		if len(s) != 2 {
			continue
		}
		libs = append(libs, types.Library{
			Name:    s[0],
			Version: s[1],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}
	return libs, nil
}

func rStripByKey(line string, key string) string {
	if pos := strings.IndexAny(line, key); pos >= 0 {
		line = strings.TrimRightFunc((line)[:pos], unicode.IsSpace)
	}
	return line
}
