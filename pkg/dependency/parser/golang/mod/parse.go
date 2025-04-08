package mod

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/mod/modfile"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	// By convention, modules with a major version equal to or above v2
	// have it as suffix in their module path.
	VCSUrlMajorVersionSuffixRegex = regexp.MustCompile(`(/v[\d]+)$`)

	// gopkg.in/user/pkg.v -> github.com/user/pkg
	VCSUrlGoPkgInRegexWithUser = regexp.MustCompile(`^gopkg\.in/([^/]+)/([^.]+)\..*$`)

	// gopkg.in without user segment
	// Example: gopkg.in/pkg.v3 -> github.com/go-pkg/pkg
	VCSUrlGoPkgInRegexWithoutUser = regexp.MustCompile(`^gopkg\.in/([^.]+)\..*$`)
)

type Parser struct {
	replace       bool // 'replace' represents if the 'replace' directive should be taken into account.
	useMinVersion bool
}

func NewParser(replace, useMinVersion bool) *Parser {
	return &Parser{
		replace:       replace,
		useMinVersion: useMinVersion,
	}
}

func (p *Parser) GetExternalRefs(path string) []ftypes.ExternalRef {
	if url := resolveVCSUrl(path); url != "" {
		return []ftypes.ExternalRef{
			{
				Type: ftypes.RefVCS,
				URL:  url,
			},
		}
	}

	return nil
}

func resolveVCSUrl(modulePath string) string {
	switch {
	case strings.HasPrefix(modulePath, "github.com/"):
		return "https://" + VCSUrlMajorVersionSuffixRegex.ReplaceAllString(modulePath, "")
	case VCSUrlGoPkgInRegexWithUser.MatchString(modulePath):
		return "https://" + VCSUrlGoPkgInRegexWithUser.ReplaceAllString(modulePath, "github.com/$1/$2")
	case VCSUrlGoPkgInRegexWithoutUser.MatchString(modulePath):
		return "https://" + VCSUrlGoPkgInRegexWithoutUser.ReplaceAllString(modulePath, "github.com/go-$1/$1")
	}

	return ""
}

// Parse parses a go.mod file
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	pkgs := make(map[string]ftypes.Package)

	goModData, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("file read error: %w", err)
	}

	modFileParsed, err := modfile.Parse("go.mod", goModData, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("go.mod parse error: %w", err)
	}

	skipIndirect := true
	if modFileParsed.Go != nil { // Old go.mod file may not include the go version. Go version for these files  is less than 1.17
		skipIndirect = lessThan(modFileParsed.Go.Version, 1, 17)
	}

	// Use minimal required go version from `toolchain` line (or from `go` line if `toolchain` is omitted) as `stdlib`.
	// Show `stdlib` only with `useMinVersion` flag.
	if p.useMinVersion {
		if toolchainVer := toolchainVersion(modFileParsed.Toolchain, modFileParsed.Go); toolchainVer != "" {
			pkgs["stdlib"] = ftypes.Package{
				ID:   packageID("stdlib", toolchainVer),
				Name: "stdlib",
				// Our versioning library doesn't support canonical (goX.Y.Z) format,
				// So we need to add `v` prefix for consistency (with module and dependency versions).
				Version:      fmt.Sprintf("v%s", toolchainVer),
				Relationship: ftypes.RelationshipDirect, // Considered a direct dependency as the main module depends on the standard packages.
			}
		}
	}

	// Required modules
	for _, require := range modFileParsed.Require {
		// Skip indirect dependencies less than Go 1.17
		if skipIndirect && require.Indirect {
			continue
		}
		pkgs[require.Mod.Path] = ftypes.Package{
			ID:                 packageID(require.Mod.Path, require.Mod.Version),
			Name:               require.Mod.Path,
			Version:            require.Mod.Version,
			Relationship:       lo.Ternary(require.Indirect, ftypes.RelationshipIndirect, ftypes.RelationshipDirect),
			ExternalReferences: p.GetExternalRefs(require.Mod.Path),
		}
	}

	// No need to evaluate the 'replace' directive for indirect dependencies
	if p.replace {
		for _, rep := range modFileParsed.Replace {
			// Check if replaced path is actually in our pkgs.
			old, ok := pkgs[rep.Old.Path]
			if !ok {
				continue
			}

			// If the replace directive has a version on the left side, make sure it matches the version that was imported.
			if rep.Old.Version != "" && old.Version != rep.Old.Version {
				continue
			}

			// Only support replace directive with version on the right side.
			// Directive without version is a local path.
			if rep.New.Version == "" {
				// Delete old pkg, since it's a local path now.
				delete(pkgs, rep.Old.Path)
				continue
			}

			// Delete old pkg, in case the path has changed.
			delete(pkgs, rep.Old.Path)

			// Add replaced package to package register.
			pkgs[rep.New.Path] = ftypes.Package{
				ID:                 packageID(rep.New.Path, rep.New.Version),
				Name:               rep.New.Path,
				Version:            rep.New.Version,
				Relationship:       old.Relationship,
				ExternalReferences: p.GetExternalRefs(rep.New.Path),
			}
		}
	}

	var deps ftypes.Dependencies
	// Main module
	if m := modFileParsed.Module; m != nil {
		root := ftypes.Package{
			ID:                 packageID(m.Mod.Path, m.Mod.Version),
			Name:               m.Mod.Path,
			Version:            m.Mod.Version,
			ExternalReferences: p.GetExternalRefs(m.Mod.Path),
			Relationship:       ftypes.RelationshipRoot,
		}

		// Store child dependencies for the root package (main module).
		// We will build a dependency graph for Direct/Indirect in `fanal` using additional files.
		dependsOn := lo.FilterMap(lo.Values(pkgs), func(pkg ftypes.Package, _ int) (string, bool) {
			return pkg.ID, pkg.Relationship == ftypes.RelationshipDirect
		})

		sort.Strings(dependsOn)
		deps = append(deps, ftypes.Dependency{
			ID:        root.ID,
			DependsOn: dependsOn,
		})

		pkgs[root.Name] = root
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))

	return pkgSlice, deps, nil
}

// lessThan checks if the Go version is less than `<majorVer>.<minorVer>`
func lessThan(ver string, majorVer, minorVer int) bool {
	if ver == "" {
		return false
	}

	ss := strings.Split(ver, ".")
	if len(ss) != 2 {
		return false
	}
	major, err := strconv.Atoi(ss[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(ss[1])
	if err != nil {
		return false
	}

	return major <= majorVer && minor < minorVer
}

// toolchainVersion returns version from `toolchain`.
// If `toolchain` is omitted - return version from `go` line (if it is version in toolchain format)
// cf. https://go.dev/doc/toolchain
func toolchainVersion(toolchain *modfile.Toolchain, goVer *modfile.Go) string {
	if toolchain != nil && toolchain.Name != "" {
		// cf. https://go.dev/doc/toolchain#name
		// `dropping the initial go and discarding off any suffix beginning with -`
		// e.g. `go1.22.5-custom` => `1.22.5`
		name, _, _ := strings.Cut(toolchain.Name, "-")
		return strings.TrimPrefix(name, "go")
	}

	if goVer != nil {
		return toolchainVersionFromGoLine(goVer.Version)
	}
	return ""
}

// toolchainVersionFromGoLine detects Go version from `go` line if `toolchain` line is omitted.
// `go` line supports the following formats:
// cf. https://go.dev/doc/toolchain#version
//   - `1.N.P`. e.g. `1.22.0`
//   - `1.N`. e.g. `1.22`
//   - `1.NrcR`. e.g. `1.22rc1`
//   - `1.NbetaR`. e.g. `1.18beta1` - only for Go 1.20 or earlier
func toolchainVersionFromGoLine(ver string) string {
	var majorMinorVer string

	if ss := strings.Split(ver, "."); len(ss) > 2 { // `1.N.P`
		majorMinorVer = strings.Join(ss[:2], ".")
	} else if v, _, rcFound := strings.Cut(ver, "rc"); rcFound { // `1.NrcR`
		majorMinorVer = v
	} else { // `1.N`
		majorMinorVer = ver
		// Add `.0` suffix to avoid user confusing.
		// See https://github.com/aquasecurity/trivy/pull/7163#discussion_r1682424315
		ver = v + ".0"
	}

	// `toolchain` has been added in go 1.21.
	// So we need to check that Go version is 1.21 or higher.
	// cf. https://github.com/aquasecurity/trivy/pull/7163#discussion_r1682424315
	if lessThan(majorMinorVer, 1, 21) {
		return ""
	}
	return ver
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.GoModule, name, version)
}
