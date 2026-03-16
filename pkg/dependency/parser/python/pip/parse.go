package pip

import (
	"bufio"
	"context"
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
	name, specs := splitNameAndSpecs(line)
	if name == "" || specs == "" {
		return nil
	}

	operators := []string{"~=", ">=", "=="}
	if !p.useMinVersion {
		operators = []string{"=="}
	}

	// Iterate over comma-separated version specifiers and find a usable version.
	for _, op := range operators {
		for spec := range strings.SplitSeq(specs, ",") {
			if ver, found := strings.CutPrefix(spec, op); found {
				return []string{name, ver}
			}
		}
	}
	return nil
}

// splitNameAndSpecs splits a line at the first character that is not part of
// a valid PEP 508 package name (i.e. not [a-zA-Z0-9._-]).
// Note: PEP 508 disallows leading/trailing [._-], but we accept them for simplicity.
// e.g. "eventlet!=0.18.3,!=0.20.1,>=0.18.2" -> ("eventlet", "!=0.18.3,!=0.20.1,>=0.18.2")
func splitNameAndSpecs(line string) (string, string) {
	for i, r := range line {
		if !isNameChar(r) {
			return line[:i], line[i:]
		}
	}
	return line, ""
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
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

// isNameChar reports whether r is a valid character in a PEP 508 package name.
// cf. https://peps.python.org/pep-0508/#names
func isNameChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-'
}

func isValidName(name string) bool {
	for _, r := range name {
		if !isNameChar(r) {
			return false
		}
	}
	return true
}

func isValidVersion(ver string) bool {
	_, err := version.Parse(ver)
	return err == nil
}
