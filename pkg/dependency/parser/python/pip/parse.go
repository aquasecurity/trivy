package pip

import (
	"bufio"
	"strings"
	"unicode"

	"golang.org/x/text/encoding"
	u "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"golang.org/x/xerrors"

	version "github.com/aquasecurity/go-pep440-version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	commentMarker string = "#"
	endColon      string = ";"
	hashMarker    string = "--"
	startExtras   string = "["
	endExtras     string = "]"
)

type Parser struct {
	logger        *log.Logger
	useMinVersion bool
}

func NewParser(useMinVersion bool) *Parser {
	return &Parser{
		logger:        log.WithPrefix("pip"),
		useMinVersion: useMinVersion,
	}
}
func (p *Parser) splitLine(line string) []string {
	separators := []string{"~=", ">=", "=="}
	// Without useMinVersion check only `==`
	if !p.useMinVersion {
		separators = []string{"=="}
	}
	for _, sep := range separators {
		if result := strings.Split(line, sep); len(result) == 2 {
			return result
		}
	}
	return nil
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	// `requirements.txt` can use byte order marks (BOM)
	// e.g. on Windows `requirements.txt` can use UTF-16LE with BOM
	// We need to override them to avoid the file being read incorrectly
	var transformer = u.BOMOverride(encoding.Nop.NewDecoder())
	decodedReader := transform.NewReader(r, transformer)

	scanner := bufio.NewScanner(decodedReader)
	var pkgs []ftypes.Package
	var lineNumber int
	for scanner.Scan() {
		lineNumber++
		text := scanner.Text()
		line := strings.ReplaceAll(text, " ", "")
		line = strings.ReplaceAll(line, `\`, "")
		line = removeExtras(line)
		line = rStripByKey(line, commentMarker)
		line = rStripByKey(line, endColon)
		line = rStripByKey(line, hashMarker)

		s := p.splitLine(line)
		if len(s) != 2 {
			continue
		}
		if p.useMinVersion && strings.HasSuffix(s[1], ".*") {
			s[1] = strings.TrimSuffix(s[1], "*") + "0"
		}

		if !isValidName(s[0]) || !isValidVersion(s[1]) {
			p.logger.Debug("Invalid package name/version in requirements.txt.", log.String("line", text))
			continue
		}

		pkgs = append(pkgs, ftypes.Package{
			Name:    s[0],
			Version: s[1],
			Locations: []ftypes.Location{
				{
					StartLine: lineNumber,
					EndLine:   lineNumber,
				},
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}
	return pkgs, nil, nil
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

func isValidName(name string) bool {
	for _, r := range name {
		// only characters [A-Z0-9._-] are allowed (case insensitive)
		// cf. https://peps.python.org/pep-0508/#names
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func isValidVersion(ver string) bool {
	_, err := version.Parse(ver)
	return err == nil
}
