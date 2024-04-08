package pip

import (
	"bufio"
	"strings"
	"unicode"

	"golang.org/x/text/encoding"
	u "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	commentMarker string = "#"
	endColon      string = ";"
	hashMarker    string = "--"
	startExtras   string = "["
	endExtras     string = "]"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	// `requirements.txt` can use byte order marks (BOM)
	// e.g. on Windows `requirements.txt` can use UTF-16LE with BOM
	// We need to override them to avoid the file being read incorrectly
	var transformer = u.BOMOverride(encoding.Nop.NewDecoder())
	decodedReader := transform.NewReader(r, transformer)

	scanner := bufio.NewScanner(decodedReader)
	var libs []types.Library
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, " ", "")
		line = strings.ReplaceAll(line, `\`, "")
		line = removeExtras(line)
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
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}
	return libs, nil, nil
}

func rStripByKey(line, key string) string {
	if pos := strings.Index(line, key); pos >= 0 {
		line = strings.TrimRightFunc((line)[:pos], unicode.IsSpace)
	}
	return line
}

func removeExtras(line string) string {
	startIndex := strings.Index(line, startExtras)
	endIndex := strings.Index(line, endExtras) + 1
	if startIndex != -1 && endIndex != -1 {
		line = line[:startIndex] + line[endIndex:]
	}
	return line
}
