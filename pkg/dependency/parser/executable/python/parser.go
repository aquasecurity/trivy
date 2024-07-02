// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package pythonparser

import (
	"bytes"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	exe "github.com/aquasecurity/trivy/pkg/dependency/parser/executable"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonPythonBinary = xerrors.New("non Python binary")
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse scans file to try to report the Python version.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	x, err := exe.OpenExe(r)
	if err != nil {
		return nil, nil, ErrUnrecognizedExe
	}

	name, vers := findVers(x)
	if vers == "" {
		return nil, nil, nil
	}

	var libs []ftypes.Package
	libs = append(libs, ftypes.Package{
		ID:      dependency.ID(ftypes.PythonExecutable, name, vers),
		Name:    name,
		Version: vers,
	})

	return libs, nil, nil
}

// findVers finds and returns the Python version in the executable x.
func findVers(x exe.Exe) (mod, vers string) {
	text, size := x.DataStart()
	data, err := x.ReadData(text, size)
	if err != nil {
		return
	}

	// Python's version pattern is [NUL]3.11.2[NUL]
	re := regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}[-._a-zA-Z0-9]*$`)
	// split by null characters, this is important so that we don't match for version number-like strings without the null character
	items := bytes.Split(data, []byte("\000"))
	for _, s := range items {
		// Extract the version number
		match := re.FindSubmatch(s)
		if match != nil {
			vers = string(match[0])
			break
		}
	}

	return "python", vers
}
