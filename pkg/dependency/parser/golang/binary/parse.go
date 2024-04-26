package binary

import (
	"cmp"
	"debug/buildinfo"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/pflag"
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

	ldflags := p.ldFlags(info.Settings)
	libs := make([]types.Library, 0, len(info.Deps)+2)
	libs = append(libs, []types.Library{
		{
			// Add main module
			Name: info.Main.Path,
			// Only binaries installed with `go install` contain semver version of the main module.
			// Other binaries use the `(devel)` version, but still may contain a stamped version
			// set via `go build -ldflags='-X main.version=<semver>'`, so we fallback to this as.
			// as a secondary source.
			// See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477.
			Version:      cmp.Or(p.checkVersion(info.Main.Path, info.Main.Version), p.parseLDFlags(ldflags)),
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

func (p *Parser) ldFlags(settings []debug.BuildSetting) []string {
	for _, setting := range settings {
		if setting.Key != "-ldflags" {
			continue
		}

		return strings.Fields(setting.Value)
	}
	return nil
}

// parseLDFlags attempts to parse the binary's version from any `-ldflags` passed to `go build` at build time.
func (p *Parser) parseLDFlags(flags []string) string {
	fset := pflag.NewFlagSet("ldflags", pflag.ContinueOnError)
	// This prevents the flag set from erroring out if other flags were provided.
	// This helps keep the implementation small, so that only the -X flag is needed.
	fset.ParseErrorsWhitelist.UnknownFlags = true
	// The shorthand name is needed here because setting the full name
	// to `X` will cause the flag set to look for `--X` instead of `-X`.
	// The flag can also be set multiple times, so a string slice is needed
	// to handle that edge case.
	var x []string
	fset.StringSliceVarP(&x, "", "X", nil, `Set the value of the string variable in importpath named name to value.
	This is only effective if the variable is declared in the source code either uninitialized
	or initialized to a constant string expression. -X will not work if the initializer makes
	a function call or refers to other variables.
	Note that before Go 1.5 this option took two separate arguments.`)
	if err := fset.Parse(flags); err != nil {
		p.logger.Error("Could not parse -ldflags found in Go binary build info", "err", err)
		return ""
	}

	for _, xx := range x {
		// It's valid to set the -X flags with quotes so we trim any that might
		// have been provided: Ex:
		//
		// -X main.version=1.0.0
		// -X=main.version=1.0.0
		// -X 'main.version=1.0.0'
		// -X='main.version=1.0.0'
		// -X="main.version=1.0.0"
		// -X "main.version=1.0.0"
		xx = strings.Trim(xx, `'"`)
		key, val, found := strings.Cut(xx, "=")
		if !found {
			p.logger.Debug("Unable to parse an -ldflags -X flag value", "got", xx)
			continue
		}

		if strings.EqualFold(key, "main.version") {
			return val
		}
	}

	return ""
}
