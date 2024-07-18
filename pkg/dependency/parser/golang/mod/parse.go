package mod

import (
	"io"
	"regexp"
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
	replace bool // 'replace' represents if the 'replace' directive should be taken into account.
}

func NewParser(replace bool) *Parser {
	return &Parser{
		replace: replace,
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

	// Use minimal required go version from `toolchain` line (or from `go` line if `toolchain` is omitted) as `stdlib`
	if toolchainVer := toolchainVersion(modFileParsed.Toolchain, modFileParsed.Go); toolchainVer != "" {
		pkgs["stdlib"] = ftypes.Package{
			ID:           packageID("stdlib", toolchainVer),
			Name:         "stdlib",
			Version:      toolchainVer,
			Relationship: ftypes.RelationshipDirect, // Considered a direct dependency as the main module depends on the standard packages.
		}
	}
	if toolchain := modFileParsed.Toolchain; toolchain != nil {

	}

	// Main module
	if m := modFileParsed.Module; m != nil {
		ver := strings.TrimPrefix(m.Mod.Version, "v")
		pkgs[m.Mod.Path] = ftypes.Package{
			ID:                 packageID(m.Mod.Path, ver),
			Name:               m.Mod.Path,
			Version:            ver,
			ExternalReferences: p.GetExternalRefs(m.Mod.Path),
			Relationship:       ftypes.RelationshipRoot,
		}
	}

	// Required modules
	for _, require := range modFileParsed.Require {
		// Skip indirect dependencies less than Go 1.17
		if skipIndirect && require.Indirect {
			continue
		}
		ver := strings.TrimPrefix(require.Mod.Version, "v")
		pkgs[require.Mod.Path] = ftypes.Package{
			ID:                 packageID(require.Mod.Path, ver),
			Name:               require.Mod.Path,
			Version:            ver,
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
			if rep.Old.Version != "" && old.Version != rep.Old.Version[1:] {
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
				ID:                 packageID(rep.New.Path, rep.New.Version[1:]),
				Name:               rep.New.Path,
				Version:            rep.New.Version[1:],
				Relationship:       old.Relationship,
				ExternalReferences: p.GetExternalRefs(rep.New.Path),
			}
		}
	}

	return lo.Values(pkgs), nil, nil
}

// lessThan checks if the Go version is less than `<majorVer>.<minorVer>`
func lessThan(ver string, majorVer, minorVer int) bool {
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
		// `go1.22.5` => `1.22.5`
		return strings.TrimPrefix(toolchain.Name, "go")
	}

	if goVer != nil && isToolchainVer(goVer.Version) {
		return goVer.Version
	}
	return ""
}

// isToolchainVer returns true if `ver` is the toolchain format version
// e.g. `1.22.0` or `1.21rc1`
// cf. https://go.dev/doc/toolchain
func isToolchainVer(ver string) bool {
	ss := strings.Split(ver, ".")
	// e.g. `1.22.0` or `1.22.0-suffix.with.dot`.
	// go toolchain discards off any suffix beginning with `-` when compares versions
	// `toolchain` has been added in go 1.21
	// So we need to check that minor version <= 21
	if len(ss) > 2 && !lessThan(strings.Join(ss[:2], "."), 1, 21) {
		return true
	}

	// Go `1.N` release candidates, which are issued before `1.N.0`, use the version syntax `1.NrcR` format.
	majorMinorVer, _, rcFound := strings.Cut(ver, "rc")
	// This is `1.N` version (e.g. `1.21`)
	// We can't be sure this is toolchain version:
	// cf. https://github.com/aquasecurity/trivy/pull/7163#discussion_r1680436648
	// Or this can be old beta format (e.g. `1.18beta2`)
	if !rcFound {
		return false
	}

	// `toolchain` has been added in go 1.21
	// So we need to check that minor version <= 21
	return !lessThan(majorMinorVer, 1, 21)
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.GoModule, name, version)
}
