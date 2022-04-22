package mod

import (
	"io"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/mod/modfile"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Parse parses a go.mod file
func Parse(r io.Reader) ([]types.Library, error) {
	libs := map[string]types.Library{}

	goModData, err := io.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("file read error: %w", err)
	}

	modFileParsed, err := modfile.Parse("go.mod", goModData, nil)
	if err != nil {
		return nil, xerrors.Errorf("go.mod parse error: %w", err)
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
			Name:     require.Mod.Path,
			Version:  require.Mod.Version[1:],
			Indirect: require.Indirect,
		}
	}

	for _, replace := range modFileParsed.Replace {
		// Check if replaced path is actually in our libs.
		old, ok := libs[replace.Old.Path]
		if !ok {
			continue
		}

		// If the replace directive has a version on the left side, make sure it matches the version that was imported.
		if replace.Old.Version != "" && old.Version != replace.Old.Version[1:] {
			continue
		}

		// Only support replace directive with version on the right side.
		// Directive without version is a local path.
		if replace.New.Version == "" {
			// Delete old lib, since it's a local path now.
			delete(libs, replace.Old.Path)
			continue
		}

		// Delete old lib, in case the path has changed.
		delete(libs, replace.Old.Path)

		// Add replaced library to library register.
		libs[replace.New.Path] = types.Library{
			Name:     replace.New.Path,
			Version:  replace.New.Version[1:],
			Indirect: old.Indirect,
		}
	}

	return maps.Values(libs), nil
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
