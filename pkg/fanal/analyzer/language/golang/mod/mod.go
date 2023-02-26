package mod

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"unicode"

	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/golang/mod"
	"github.com/aquasecurity/go-dep-parser/pkg/golang/sum"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(types.GoMod, newGoModAnalyzer)
}

const version = 2

var (
	requiredFiles = []string{
		types.GoMod,
		types.GoSum,
	}
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|README|NOTICE).*$`)
)

type gomodAnalyzer struct {
	modParser godeptypes.Parser
	sumParser godeptypes.Parser
}

func newGoModAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gomodAnalyzer{
		modParser: mod.NewParser(),
		sumParser: sum.NewParser(),
	}, nil
}

func (a *gomodAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	err := fs.WalkDir(input.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() {
			return nil
		}

		dir, file := filepath.Split(path)
		if file != types.GoMod {
			return nil
		}

		// Parse go.mod
		gomod, err := parse(input.FS, path, a.modParser)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if gomod == nil {
			return nil
		}

		if lessThanGo117(gomod) {
			// e.g. /app/go.mod => /app/go.sum
			sumPath := filepath.Join(dir, types.GoSum)
			gosum, err := parse(input.FS, sumPath, a.sumParser)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return xerrors.Errorf("parse error: %w", err)
			}
			mergeGoSum(gomod, gosum)
		}

		apps = append(apps, *gomod)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	if err = fillLicenses(apps); err != nil {
		return nil, xerrors.Errorf("unable to identify licenses: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a *gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a *gomodAnalyzer) Version() int {
	return version
}

func parse(fsys fs.FS, path string, parser godeptypes.Parser) (*types.Application, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	file, ok := f.(dio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// Parse go.mod or go.sum
	libs, deps, err := parser.Parse(file)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", path, err)
	}
	return language.ToApplication(types.GoModule, path, "", libs, deps), nil
}

func lessThanGo117(gomod *types.Application) bool {
	for _, lib := range gomod.Libraries {
		// The indirect field is populated only in Go 1.17+
		if lib.Indirect {
			return false
		}
	}
	return true
}

func mergeGoSum(gomod, gosum *types.Application) {
	if gomod == nil || gosum == nil {
		return
	}
	uniq := map[string]types.Package{}
	for _, lib := range gomod.Libraries {
		// It will be used for merging go.sum.
		uniq[lib.Name] = lib
	}

	// For Go 1.16 or less, we need to merge go.sum into go.mod.
	for _, lib := range gosum.Libraries {
		// Skip dependencies in go.mod so that go.mod should be preferred.
		if _, ok := uniq[lib.Name]; ok {
			continue
		}

		// This dependency doesn't exist in go.mod, so it must be an indirect dependency.
		lib.Indirect = true
		uniq[lib.Name] = lib
	}

	gomod.Libraries = maps.Values(uniq)
}

func fillLicenses(apps []types.Application) error {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}

	// $GOPATH/pkg/mod
	modPath := filepath.Join(gopath, "pkg", "mod")
	if !fsutils.DirExists(modPath) {
		log.Logger.Debugf("GOPATH (%s) not found. Need 'go mod download' to fill license information", modPath)
		return nil
	}

	licenses := map[string][]string{}
	for i, app := range apps {
		for j, lib := range app.Libraries {
			libID := lib.Name + "@v" + lib.Version
			if l, ok := licenses[libID]; ok {
				// Fill licenses
				apps[i].Libraries[j].Licenses = l
				continue
			}

			// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v1.0.0
			modDir := filepath.Join(modPath, fmt.Sprintf("%s@v%s", normalizeModName(lib.Name), lib.Version))
			l, err := findLicense(modDir)
			if err != nil {
				return xerrors.Errorf("golang license error: %w", err)
			} else if l == nil || len(l.Findings) == 0 {
				continue
			}
			licenseNames := lo.Map(l.Findings, func(finding types.LicenseFinding, _ int) string {
				return finding.Name
			})
			// Cache the detected licenses
			licenses[libID] = licenseNames

			// Fill licenses
			apps[i].Libraries[j].Licenses = licenseNames
		}
	}
	return nil
}

func findLicense(dir string) (*types.LicenseFile, error) {
	var license *types.LicenseFile
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() {
			return nil
		}
		if !licenseRegexp.MatchString(filepath.Base(path)) {
			return nil
		}
		// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237/LICENSE
		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("file (%s) open error: %w", path, err)
		}
		defer f.Close()

		l, err := licensing.Classify(path, f)
		if err != nil {
			return xerrors.Errorf("license classify error: %w", err)
		}
		// License found
		if l != nil && len(l.Findings) > 0 {
			license = l
			return io.EOF
		}
		return nil
	})
	// The module path may not exist
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("finding a known open source license: %w", err)
	}
	return license, nil
}

// normalizeModName escapes upper characters
// e.g. 'github.com/BurntSushi/toml' => 'github.com/!burnt!sushi'
func normalizeModName(name string) string {
	var newName []rune
	for _, c := range name {
		if unicode.IsUpper(c) {
			// 'A' => '!a'
			newName = append(newName, '!', unicode.ToLower(c))
		} else {
			newName = append(newName, c)
		}
	}
	return string(newName)
}
