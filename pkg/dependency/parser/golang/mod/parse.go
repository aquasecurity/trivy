package mod

import (
	"io"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/mod/modfile"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
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

func NewParser(replace bool) types.Parser {
	return &Parser{
		replace: replace,
	}
}

func (p *Parser) GetExternalRefs(path string) []types.ExternalRef {
	if url := resolveVCSUrl(path); url != "" {
		return []types.ExternalRef{
			{
				Type: types.RefVCS,
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
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	libs := make(map[string]types.Library)

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
		skipIndirect = lessThan117(modFileParsed.Go.Version)
	}

	for _, require := range modFileParsed.Require {
		// Skip indirect dependencies less than Go 1.17
		if skipIndirect && require.Indirect {
			continue
		}
		libs[require.Mod.Path] = types.Library{
			ID:                 packageID(require.Mod.Path, require.Mod.Version[1:]),
			Name:               require.Mod.Path,
			Version:            require.Mod.Version[1:],
			Indirect:           require.Indirect,
			ExternalReferences: p.GetExternalRefs(require.Mod.Path),
		}
	}

	// No need to evaluate the 'replace' directive for indirect dependencies
	if p.replace {
		for _, rep := range modFileParsed.Replace {
			// Check if replaced path is actually in our libs.
			old, ok := libs[rep.Old.Path]
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
				// Delete old lib, since it's a local path now.
				delete(libs, rep.Old.Path)
				continue
			}

			// Delete old lib, in case the path has changed.
			delete(libs, rep.Old.Path)

			// Add replaced library to library register.
			libs[rep.New.Path] = types.Library{
				ID:                 packageID(rep.New.Path, rep.New.Version[1:]),
				Name:               rep.New.Path,
				Version:            rep.New.Version[1:],
				Indirect:           old.Indirect,
				ExternalReferences: p.GetExternalRefs(rep.New.Path),
			}
		}
	}

	return maps.Values(libs), nil, nil
}

// Check if the Go version is less than 1.17
func lessThan117(ver string) bool {
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

	return major <= 1 && minor < 17
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.GoModule, name, version)
}
