package cargo

import (
	"context"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/python/poetry"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeCargo, newCargoAnalyzer)
}

const version = 1

var requiredFiles = []string{
	types.CargoLock,
	types.CargoToml,
}

type cargoAnalyzer struct {
	lockParser godeptypes.Parser
	comparer   compare.GenericComparer
}

func newCargoAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &cargoAnalyzer{
		lockParser: poetry.NewParser(),
		comparer:   compare.GenericComparer{},
	}, nil
}

func (a cargoAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.CargoLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// Parse Cargo.lock
		app, err := a.parseCargoLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Cargo.toml alongside Cargo.lock to identify the direct dependencies
		if err = a.removeDevDependencies(input.FS, filepath.Dir(path), app); err != nil {
			return err
		}
		sort.Sort(types.Packages(app.Libraries))
		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("cargo walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a cargoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a cargoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCargo
}

func (a cargoAnalyzer) Version() int {
	return version
}

func (a cargoAnalyzer) parseCargoLock(path string, r dio.ReadSeekerAt) (*types.Application, error) {
	libs, deps, err := a.lockParser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Cargo.lock: %w", err)
	}
	return language.ToApplication(types.Cargo, path, "", libs, deps), nil
}

func (a cargoAnalyzer) removeDevDependencies(fsys fs.FS, dir string, app *types.Application) error {
	packageJsonPath := filepath.Join(dir, types.CargoToml)
	directDeps, err := a.parseCargoToml(fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Yarn: %s not found", packageJsonPath)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", dir, err)
	}

	// cargo.toml file can contain same libraries with different versions
	// save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	pkgs := map[string]types.Package{}
	for name, constraint := range directDeps {
		for _, pkg := range app.Libraries {
			if pkg.Name != name {
				continue
			}

			if match, err := a.matchVersion(pkg.Version, constraint); err != nil {
				return xerrors.Errorf("unable to match version for %s", pkg.Name)
			} else if match {
				// Mark as a direct dependency
				pkg.Indirect = false
				pkgs[pkg.ID] = pkg
				break
			}
		}
	}

	// Walk indirect dependencies
	// Since it starts from direct dependencies, devDependencies will not appear in this walk.
	for _, pkg := range pkgs {
		a.walkIndirectDependencies(pkg, pkgIDs, pkgs)
	}

	pkgSlice := maps.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save only prod libraries
	app.Libraries = pkgSlice
	return nil
}

type cargoToml struct {
	Dependencies map[string]interface{} `toml:"dependencies"`
}

func (a cargoAnalyzer) parseCargoToml(fsys fs.FS, path string) (map[string]string, error) {
	// Parse Cargo.json
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	tomlFile := cargoToml{}
	deps := map[string]string{}
	_, err = toml.NewDecoder(f).Decode(&tomlFile)
	if err != nil {
		return nil, xerrors.Errorf("toml decode error: %w", err)
	}

	for name, value := range tomlFile.Dependencies {
		switch ver := value.(type) {
		case string:
			// e.g. regex = "1.5"
			deps[name] = ver
		case map[string]interface{}:
			// e.g. serde = { version = "1.0", features = ["derive"] }
			for k, v := range ver {
				if k == "version" {
					deps[name] = v.(string)
				}
			}
		}
	}

	return deps, nil
}

func (a cargoAnalyzer) walkIndirectDependencies(pkg types.Package, pkgIDs map[string]types.Package, deps map[string]types.Package) {
	for _, pkgID := range pkg.DependsOn {
		if _, ok := deps[pkgID]; ok {
			continue
		}

		dep, ok := pkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		deps[dep.ID] = dep
		a.walkIndirectDependencies(dep, pkgIDs, deps)
	}
}

func (a cargoAnalyzer) matchVersion(currentVersion, constraint string) (bool, error) {
	// there are next prefixes:
	// `>=`, `>`, `<`, `=`, ``, `^`
	switch {
	case strings.HasPrefix(constraint, "<") || strings.HasPrefix(constraint, ">"):
		match, err := a.comparer.MatchVersion(currentVersion, constraint)
		if err != nil {
			return false, xerrors.Errorf("unable to match version: %w", err)
		}
		return match, nil
	case strings.HasPrefix(constraint, "="):
		// `=` prefix uses max version for major/minor/patch... version
		// e.g. for `memchr`:  2 => 2.5.0; 2.4 => 2.4.1
		constraint = strings.TrimLeft(constraint, "=")
		constraint = strings.TrimSpace(constraint)
		splitConstraint := strings.Split(constraint, ".")
		splitVersion := strings.Split(currentVersion, ".")
		shortCurrentVersion := strings.Join(splitVersion[:len(splitConstraint)], ".")
		return constraint == shortCurrentVersion, nil
	default:
		// `` == `^`
		if !strings.HasPrefix(constraint, "^") {
			constraint = fmt.Sprintf("^ %s", constraint)
		}
		match, err := a.comparer.MatchVersion(currentVersion, constraint)
		if err != nil {
			return false, xerrors.Errorf("unable to match version: %w", err)
		}
		return match, nil
	}
}
