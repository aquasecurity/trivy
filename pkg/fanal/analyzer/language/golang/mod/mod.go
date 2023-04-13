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
	// root go.mod/go.sum
	modParser godeptypes.Parser
	sumParser godeptypes.Parser

	// go.mod/go.sum in dependencies
	leafModParser godeptypes.Parser
}

func newGoModAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gomodAnalyzer{
		modParser:     mod.NewParser(true), // Only the root module should replace
		sumParser:     sum.NewParser(),
		leafModParser: mod.NewParser(false),
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

	if err = a.fillAdditionalData(apps); err != nil {
		log.Logger.Warnf("Unable to collect additional info: %s", err)
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

// fillAdditionalData collects licenses and dependency relationships, then update applications.
func (a *gomodAnalyzer) fillAdditionalData(apps []types.Application) error {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}

	// $GOPATH/pkg/mod
	modPath := filepath.Join(gopath, "pkg", "mod")
	if !fsutils.DirExists(modPath) {
		log.Logger.Debugf("GOPATH (%s) not found. Need 'go mod download' to fill licenses and dependency relationships", modPath)
		return nil
	}

	licenses := map[string][]string{}
	for i, app := range apps {
		// Actually used dependencies
		usedLibs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
			return pkg.Name, pkg
		})
		for j, lib := range app.Libraries {
			if l, ok := licenses[lib.ID]; ok {
				// Fill licenses
				apps[i].Libraries[j].Licenses = l
				continue
			}

			// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v1.0.0
			modDir := filepath.Join(modPath, fmt.Sprintf("%s@v%s", normalizeModName(lib.Name), lib.Version))

			// Collect licenses
			if licenseNames, err := findLicense(modDir); err != nil {
				return xerrors.Errorf("license error: %w", err)
			} else {
				// Cache the detected licenses
				licenses[lib.ID] = licenseNames

				// Fill licenses
				apps[i].Libraries[j].Licenses = licenseNames
			}

			// Collect dependencies of the direct dependency
			if dep, err := a.collectDeps(modDir, lib.ID); err != nil {
				return xerrors.Errorf("dependency graph error: %w", err)
			} else if dep.ID == "" {
				// go.mod not found
				continue
			} else {
				// Filter out unused dependencies and convert module names to module IDs
				apps[i].Libraries[j].DependsOn = lo.FilterMap(dep.DependsOn, func(modName string, _ int) (string, bool) {
					if m, ok := usedLibs[modName]; !ok {
						return "", false
					} else {
						return m.ID, true
					}
				})
			}
		}
	}
	return nil
}

func (a *gomodAnalyzer) collectDeps(modDir string, pkgID string) (godeptypes.Dependency, error) {
	// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237/go.mod
	modPath := filepath.Join(modDir, "go.mod")
	f, err := os.Open(modPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Unable to identify dependencies of %s as it doesn't support Go modules", pkgID)
		return godeptypes.Dependency{}, nil
	} else if err != nil {
		return godeptypes.Dependency{}, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	// Parse go.mod under $GOPATH/pkg/mod
	libs, _, err := a.leafModParser.Parse(f)
	if err != nil {
		return godeptypes.Dependency{}, xerrors.Errorf("%s parse error: %w", modPath, err)
	}

	// Filter out indirect dependencies
	dependsOn := lo.FilterMap(libs, func(lib godeptypes.Library, index int) (string, bool) {
		return lib.Name, !lib.Indirect
	})

	return godeptypes.Dependency{
		ID:        pkgID,
		DependsOn: dependsOn,
	}, nil
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
	return language.Parse(types.GoModule, path, file, parser)
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

func findLicense(dir string) ([]string, error) {
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
	} else if license == nil || len(license.Findings) == 0 {
		return nil, nil
	}

	return lo.Map(license.Findings, func(finding types.LicenseFinding, _ int) string {
		return finding.Name
	}), nil
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
