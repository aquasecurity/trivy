package binary

import (
	"debug/buildinfo"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonGoBinary     = xerrors.New("non go binary")
)

// convertError detects buildinfo.errUnrecognizedFormat and convert to
// ErrUnrecognizedExe and convert buildinfo.errNotGoExe to ErrNonGoBinary
func convertError(err error) error {
	errText := err.Error()
	if strings.HasSuffix(errText, "unrecognized file format") {
		return ErrUnrecognizedExe
	}
	if strings.HasSuffix(errText, "not a Go executable") {
		return ErrNonGoBinary
	}

	return err
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

// Parse scans file to try to report the Go and module versions.
func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	info, err := buildinfo.Read(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	libs := make([]types.Library, 0, len(info.Deps))

	for _, dep := range info.Deps {
		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}

		libs = append(libs, types.Library{
			Name:    mod.Path,
			Version: mod.Version,
		})
	}

	return libs, nil, nil
}
