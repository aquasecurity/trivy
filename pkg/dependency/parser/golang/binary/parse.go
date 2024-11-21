package binary

import (
	"cmp"
	"debug/buildinfo"
	"fmt"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/pflag"
	"golang.org/x/mod/semver"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("gobinary"),
	}
}

// Parse scans file to try to report the Go and module versions.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	info, err := buildinfo.Read(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	// Ex: "go1.22.3 X:boringcrypto"
	stdlibVersion := strings.TrimPrefix(info.GoVersion, "go")
	stdlibVersion, _, _ = strings.Cut(stdlibVersion, " ")
	// Add the `v` prefix to be consistent with module and dependency versions.
	stdlibVersion = fmt.Sprintf("v%s", stdlibVersion)

	ldflags := p.ldFlags(info.Settings)
	pkgs := make(ftypes.Packages, 0, len(info.Deps)+2)
	pkgs = append(pkgs, ftypes.Package{
		// Add the Go version used to build this binary.
		ID:           dependency.ID(ftypes.GoBinary, "stdlib", stdlibVersion),
		Name:         "stdlib",
		Version:      stdlibVersion,
		Relationship: ftypes.RelationshipDirect, // Considered a direct dependency as the main module depends on the standard packages.
	})

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

		version := p.checkVersion(mod.Path, mod.Version)
		pkgs = append(pkgs, ftypes.Package{
			ID:           dependency.ID(ftypes.GoBinary, mod.Path, version),
			Name:         mod.Path,
			Version:      version,
			Relationship: ftypes.RelationshipUnknown,
		})
	}

	// There are times when gobinaries don't contain Main information.
	// e.g. `Go` binaries (e.g. `go`, `gofmt`, etc.)
	var deps []ftypes.Dependency
	if info.Main.Path != "" {
		// Only binaries installed with `go install` contain semver version of the main module.
		// Other binaries use the `(devel)` version, but still may contain a stamped version
		// set via `go build -ldflags='-X main.version=<semver>'`, so we fallback to this as.
		// as a secondary source.
		// See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477.
		version := cmp.Or(p.checkVersion(info.Main.Path, info.Main.Version), p.ParseLDFlags(info.Main.Path, ldflags))
		root := ftypes.Package{
			ID:           dependency.ID(ftypes.GoBinary, info.Main.Path, version),
			Name:         info.Main.Path,
			Version:      version,
			Relationship: ftypes.RelationshipRoot,
		}

		depIDs := lo.Map(pkgs, func(pkg ftypes.Package, _ int) string {
			return pkg.ID
		})
		sort.Strings(depIDs)

		deps = []ftypes.Dependency{
			{
				ID:        root.ID,
				DependsOn: depIDs, // Consider all packages as dependencies of the main module.
			},
		}
		// Add main module
		pkgs = append(pkgs, root)
	}

	sort.Sort(pkgs)
	return pkgs, deps, nil
}

// checkVersion detects `(devel)` versions, removes them and adds a debug message about it.
func (p *Parser) checkVersion(name, version string) string {
	if version == "(devel)" {
		p.logger.Debug("Unable to detect main module's dependency version - `(devel)` is used", log.String("dependency", name))
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

// ParseLDFlags attempts to parse the binary's version from any `-ldflags` passed to `go build` at build time.
func (p *Parser) ParseLDFlags(name string, flags []string) string {
	p.logger.Debug("Parsing dependency's build info settings", "dependency", name, "-ldflags", flags)
	fset := pflag.NewFlagSet("ldflags", pflag.ContinueOnError)
	// This prevents the flag set from erroring out if other flags were provided.
	// This helps keep the implementation small, so that only the -X flag is needed.
	fset.ParseErrorsWhitelist.UnknownFlags = true
	// The shorthand name is needed here because setting the full name
	// to `X` will cause the flag set to look for `--X` instead of `-X`.
	// The flag can also be set multiple times, so a string slice is needed
	// to handle that edge case.
	var x map[string]string
	fset.StringToStringVarP(&x, "", "X", nil, "")
	if err := fset.Parse(flags); err != nil {
		p.logger.Error("Could not parse -ldflags found in build info", log.Err(err))
		return ""
	}

	// foundVersions contains discovered versions by type.
	// foundVersions doesn't contain duplicates. Versions are filled into first corresponding category.
	// Possible elements(categories):
	//   [0]: Versions using format `github.com/<module_owner>/<module_name>/cmd/**/*.<version>=x.x.x`
	//   [1]: Versions that use prefixes from `defaultPrefixes`
	//   [2]: Other versions
	var foundVersions = make([][]string, 3)
	defaultPrefixes := []string{
		"main",
		"common",
		"version",
		"cmd",
	}
	for key, val := range x {
		// It's valid to set the -X flags with quotes so we trim any that might
		// have been provided: Ex:
		//
		// -X main.version=1.0.0
		// -X=main.version=1.0.0
		// -X 'main.version=1.0.0'
		// -X='main.version=1.0.0'
		// -X="main.version=1.0.0"
		// -X "main.version=1.0.0"
		key = strings.TrimLeft(key, `'`)
		val = strings.TrimRight(val, `'`)
		if isVersionXKey(key) && isValidSemVer(val) {
			switch {
			case strings.HasPrefix(key, name+"/cmd/"):
				foundVersions[0] = append(foundVersions[0], val)
			case slices.Contains(defaultPrefixes, strings.ToLower(versionPrefix(key))):
				foundVersions[1] = append(foundVersions[1], val)
			default:
				foundVersions[2] = append(foundVersions[2], val)
			}
		}
	}

	return p.chooseVersion(name, foundVersions)
}

// chooseVersion chooses version from found versions
// Categories order:
// module name with `cmd` => versions with default prefixes => other versions
// See more in https://github.com/aquasecurity/trivy/issues/6702#issuecomment-2122271427
func (p *Parser) chooseVersion(moduleName string, vers [][]string) string {
	for _, versions := range vers {
		// Versions for this category was not found
		if len(versions) == 0 {
			continue
		}

		// More than 1 version for one category.
		// Use empty version.
		if len(versions) > 1 {
			p.logger.Debug("Unable to detect dependency version. `-ldflags` build info settings contain more than one version. Empty version used.", log.String("dependency", moduleName))
			return ""
		}
		return versions[0]
	}

	p.logger.Debug("Unable to detect dependency version. `-ldflags` build info settings don't contain version flag. Empty version used.", log.String("dependency", moduleName))
	return ""
}

func isVersionXKey(key string) bool {
	key = strings.ToLower(key)
	// The check for a 'ver' prefix enables the parser to pick up Trivy's own version value that's set.
	return strings.HasSuffix(key, ".version") || strings.HasSuffix(key, ".ver")
}

func isValidSemVer(ver string) bool {
	// semver.IsValid strictly checks for the v prefix so prepending 'v'
	// here and checking validity again increases the chances that we
	// parse a valid semver version.
	return semver.IsValid(ver) || semver.IsValid("v"+ver)
}

// versionPrefix returns version prefix from `-ldflags` flag key
// e.g.
//   - `github.com/aquasecurity/trivy/pkg/version/app.ver` => `version`
//   - `github.com/google/go-containerregistry/cmd/crane/common.ver` => `common`
func versionPrefix(s string) string {
	// Trim module part.
	// e.g. `github.com/aquasecurity/trivy/pkg/Version.version` => `Version.version`
	if lastIndex := strings.LastIndex(s, "/"); lastIndex > 0 {
		s = s[lastIndex+1:]
	}

	s, _, _ = strings.Cut(s, ".")
	return strings.ToLower(s)
}
