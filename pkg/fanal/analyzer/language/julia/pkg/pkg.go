package pkgjl

import (
	"context"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	julia "github.com/aquasecurity/trivy/pkg/dependency/parser/julia/manifest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJulia, newJuliaAnalyzer)
}

const version = 1

var requiredFiles = []string{
	types.JuliaManifest,
	types.JuliaProject,
}

type juliaAnalyzer struct {
	lockParser language.Parser
	logger     *log.Logger
	crc        *crc32.Table
}

type Project struct {
	Dependencies map[string]string `toml:"deps"`
	Extras       map[string]string `toml:"extras"`
	License      string            `toml:"license"`
}

func newJuliaAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &juliaAnalyzer{
		lockParser: julia.NewParser(),
		logger:     log.WithPrefix("julia"),
		crc:        crc32.MakeTable(crc32.Castagnoli),
	}, nil
}

func (a juliaAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.JuliaManifest
	}

	depot, depotErr := findDepot()
	if depotErr != nil {
		a.logger.Warn("Failed to find Julia depot, license detection is disabled for Julia")
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		// Parse Manifest.toml
		app, err := a.parseJuliaManifest(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Project.toml alongside Manifest.toml to identify the direct dependencies. This mutates `app`.
		if err = a.analyzeDependencies(input.FS, filepath.Dir(path), app); err != nil {
			a.logger.Warn("Unable to parse file to analyze dependencies",
				log.FilePath(filepath.Join(filepath.Dir(path), types.JuliaProject)), log.Err(err))
		}

		// Fill licenses
		if depotErr == nil {
			for i, lib := range app.Packages {
				licenses, err := a.getLicenses(lib, depot)
				if err == nil {
					app.Packages[i].Licenses = licenses
				} else {
					a.logger.Info("Failed to find licenses for package", "name", lib.Name, "UUID", lib.ID, "error", err.Error()) // FIXME make debug
				}
			}
		}

		sort.Sort(app.Packages)
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("julia walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a juliaAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a juliaAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJulia
}

func (a juliaAnalyzer) Version() int {
	return version
}

func (a juliaAnalyzer) parseJuliaManifest(path string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Julia, path, r, a.lockParser)
}

func (a juliaAnalyzer) analyzeDependencies(fsys fs.FS, dir string, app *types.Application) error {
	projectPath := filepath.Join(dir, types.JuliaProject)
	project, err := parseJuliaProject(fsys, projectPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("Julia project not found", log.String("PROJECT_PATH", projectPath))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", projectPath, err)
	}

	pkgs := walkDependencies(project.Dependencies, app.Packages, false)
	devPkgs := walkDependencies(project.Extras, app.Packages, true)
	app.Packages = append(pkgs, devPkgs...)
	return nil
}

// Parses Project.toml
func parseJuliaProject(fsys fs.FS, path string) (Project, error) {
	proj := Project{}
	f, err := fsys.Open(path)
	if err != nil {
		return proj, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err = toml.NewDecoder(f).Decode(&proj); err != nil {
		return proj, xerrors.Errorf("decode error: %w", err)
	}
	return proj, nil
}

// Marks the given direct dependencies as direct, then marks those packages' dependencies as indirect.
// Marks all encountered packages' Dev flag according to `dev`.
// Modifies the packages in `allPackages`.
func walkDependencies(directDeps map[string]string, allPackages types.Packages, dev bool) []types.Package {
	pkgsByID := lo.SliceToMap(allPackages, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	// Everything in `directDeps` is assumed to be direct
	visited := make(map[string]types.Package)
	for _, uuid := range directDeps {
		if pkg, ok := pkgsByID[uuid]; ok {
			pkg.Indirect = false
			pkg.Dev = dev
			visited[pkg.ID] = pkg
		}
	}

	// Identify indirect dependencies
	for _, pkg := range visited {
		walkIndirectDependencies(pkg, pkgsByID, visited)
	}

	return lo.Values(visited)
}

// Marks all indirect dependencies as indirect. Starts from `rootPkg`. Visited deps are added to `visited`.
func walkIndirectDependencies(rootPkg types.Package, allPkgIDs, visited map[string]types.Package) {
	for _, pkgID := range rootPkg.DependsOn {
		if _, ok := visited[pkgID]; ok {
			continue
		}

		dep, ok := allPkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		dep.Dev = rootPkg.Dev
		visited[dep.ID] = dep
		walkIndirectDependencies(dep, allPkgIDs, visited)
	}
}

func (a juliaAnalyzer) getLicenses(lib types.Package, depot string) ([]string, error) {
	// https://github.com/JuliaLang/Pkg.jl/blob/15ef1a1d1dd873fbb265a24ecc02554e364f0063/src/Operations.jl#L48

	// If the package has a path specified in the manifest:
	if len(lib.InstalledFiles) > 0 {
		pkgDir := lib.InstalledFiles[0] // the path field from the manifest, set by the parser
		return a.getLicensesInDir(pkgDir)
	}

	// If the package has a tree hash:
	libNameDir := path.Join(depot, "packages", lib.Name)
	a.logger.Info("scanning", "dir", libNameDir) // FIXME remove
	if fsutils.DirExists(libNameDir) {
		return a.getLicensesFromDepotPackage(libNameDir)
	}

	// If the package is a stdlib:
	return []string{"MIT"}, nil
}

func (a juliaAnalyzer) getLicensesFromDepotPackage(libNameDir string) ([]string, error) {
	// Note we don't actually compute the tree hash or version slug because that gets very complicated and Julia could
	// change it at any time. Therefore, we only look for the latest modified installation of the package.
	subdirs, err := os.ReadDir(libNameDir)
	if err != nil {
		return nil, err
	}

	mostRecentTime := time.Unix(0, 0)
	var mostRecentSubdir fs.DirEntry
	for _, subdir := range subdirs {
		if !subdir.IsDir() {
			continue
		}
		info, err := subdir.Info()
		if err != nil {
			return nil, err
		}
		if info.ModTime().After(mostRecentTime) {
			mostRecentTime = info.ModTime()
			mostRecentSubdir = subdir
		}
	}

	libDir := path.Join(libNameDir, mostRecentSubdir.Name())
	return a.getLicensesInDir(libDir)
}

func (a juliaAnalyzer) getLicensesInDir(libDir string) ([]string, error) {
	f, err := os.Open(path.Join(libDir, "Project.toml"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	project := Project{}
	if _, err = toml.NewDecoder(f).Decode(&project); err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
	}

	a.logger.Info("project license field", "dir", libDir, "license", project.License)

	// Projects might specify a license, but it's not required
	if project.License != "" {
		return []string{project.License}, nil
	}

	// Many projects have a license but don't set it in their project file, so try to detect the license using the content
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if name == "license" || name == "license.txt" || name == "license.md" {
			buf, err := os.ReadFile(path.Join(libDir, entry.Name()))
			if err != nil {
				return nil, err
			}
			license, err := detectLicenseFromString(string(buf))
			if err != nil {
				return nil, err
			}
			return []string{license}, nil
		}
	}

	// There is no license information at all
	return nil, nil
}

func detectLicenseFromString(s string) (string, error) {
	s = strings.ToLower(s)
	if strings.Contains(s, "mit license") || strings.Contains(s, "mit expat license") || strings.Contains(s, "mit \"expat\" license") {
		return "MIT", nil
	} else {
		return "", xerrors.Errorf("could not detect license from content")
	}
}

func findDepot() (string, error) {
	home, _ := os.UserHomeDir()
	possibleDepotDirs := []string{
		// Users can set JULIA_DEPOT_PATH https://pkgdocs.julialang.org/v1/glossary/
		os.Getenv("JULIA_DEPOT_PATH"),
		// The default depot path is ~/.julia
		path.Join(home, ".julia"),
	}

	for _, dir := range possibleDepotDirs {
		if dir != "" {
			if fsutils.DirExists(dir) {
				return dir, nil
			}
		}
	}

	return "", xerrors.Errorf("failed to find Julia depot")
}
