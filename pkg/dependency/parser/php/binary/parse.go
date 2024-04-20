// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package binary

import (
	"bytes"
	"regexp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonPythonBinary = xerrors.New("non Python binary")
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

// Parse scans file to try to report the Python version.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	x, err := openExe(r)
	if err != nil {
		return nil, nil, ErrUnrecognizedExe
	}

	name, vers := findVers(x)
	if vers == "" {
		return nil, nil, nil
	}

	var libs []types.Library
	libs = append(libs, types.Library{
		ID: packageID(name, vers),
		Name:    name,
		Version: vers,
	})

	return libs, nil, nil
}

// findVers finds and returns the PHP version in the executable x.
func findVers(x exe) (vers, mod string) {
	text, size := x.DataStart()
	data, err := x.ReadData(text, size)
	if err != nil {
		return
	}

	re := regexp.MustCompile(`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`)
	// split by null characters
	items := bytes.Split(data, []byte("\000"))
	for _, s := range items {
		// Extract the version number
		match := re.FindSubmatch(s)
		if match != nil {
			vers = string(match[1])
			break
		}
	}

	return "php", vers
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.PhpGeneric, name, version)
}
