package binary

import (
	"debug/buildinfo"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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

type Parser struct {
	logger *log.Logger
}

func NewParser() types.Parser {
	return &Parser{
		logger: log.WithPrefix("gobinary"),
	}
}

// Parse scans file to try to report the Go and module versions.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	info, err := buildinfo.Read(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	libs := make([]types.Library, 0, len(info.Deps)+2)
	libs = append(libs, []types.Library{
		{
			// Add main module
			Name: info.Main.Path,
			// Only binaries installed with `go install` contain semver version of the main module.
			// Other binaries use the `(devel)` version.
			// See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477.
			Version:      p.checkVersion(info.Main.Path, info.Main.Version),
			Relationship: types.RelationshipRoot,
		},
		{
			// Add the Go version used to build this binary.
			Name:         "stdlib",
			Version:      strings.TrimPrefix(info.GoVersion, "go"),
			Relationship: types.RelationshipDirect, // Considered a direct dependency as the main module depends on the standard packages.
		},
	}...)

	for _, dep := range info.Deps {
		// binaries with old go version may incorrectly add module in Deps
		// In this case Path == "", Version == "Devel"
		// we need to skip this
		if dep.Path == "" {
			continue
		}

		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}

		libs = append(libs, types.Library{
			Name:    mod.Path,
			Version: p.checkVersion(mod.Path, mod.Version),
		})
	}

	sort.Sort(types.Libraries(libs))
	return libs, nil, nil
}

// checkVersion detects `(devel)` versions, removes them and adds a debug message about it.
func (p *Parser) checkVersion(name, version string) string {
	if version == "(devel)" {
		p.logger.Debug("Unable to detect dependency version (`(devel)` is used). Version will be empty.", log.String("dependency", name))
		return ""
	}
	return version
}
