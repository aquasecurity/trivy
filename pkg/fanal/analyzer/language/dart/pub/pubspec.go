package pub

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/dart/pub"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePubSpecLock, newPubSpecLockAnalyzer)
}

const (
	version             = 2
	pubSpecYamlFileName = "pubspec.yaml"
)

// pubSpecLockAnalyzer analyzes `pubspec.lock`
type pubSpecLockAnalyzer struct {
	logger *log.Logger
	parser language.Parser
}

func newPubSpecLockAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pubSpecLockAnalyzer{
		logger: log.WithPrefix("pub"),
		parser: pub.NewParser(opts.DetectionPriority == types.PriorityComprehensive),
	}, nil
}

func (a pubSpecLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	// get all DependsOn from cache dir
	// lib ID -> DependsOn names
	allDependsOn, err := a.findDependsOn()
	if err != nil {
		a.logger.Warn("Unable to parse cache dir", log.Err(err))
	}

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.PubSpecLock
	}

	err = fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(types.Pub, path, r, a.parser)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}

		if app == nil {
			return nil
		}

		if allDependsOn != nil {
			// Required to search for library versions for DependsOn.
			pkgs := lo.SliceToMap(app.Packages, func(lib types.Package) (string, string) {
				return lib.Name, lib.ID
			})

			for i, lib := range app.Packages {
				var dependsOn []string
				for _, depName := range allDependsOn[lib.ID] {
					if depID, ok := pkgs[depName]; ok {
						dependsOn = append(dependsOn, depID)
					}
				}
				app.Packages[i].DependsOn = dependsOn
			}
		}

		sort.Sort(app.Packages)
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a pubSpecLockAnalyzer) findDependsOn() (map[string][]string, error) {
	dir := cacheDir()
	if !fsutils.DirExists(dir) {
		a.logger.Debug("Cache dir not found. Need 'dart pub get' to fill dependency relationships",
			log.String("dir", dir))
		return nil, nil
	}

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == pubSpecYamlFileName
	}

	deps := make(map[string][]string)
	if err := fsutils.WalkDir(os.DirFS(dir), ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		id, dependsOn, err := parsePubSpecYaml(r)
		if err != nil {
			a.logger.Debug("Unable to parse pubspec.yaml", log.FilePath(path), log.Err(err))
			return nil
		}
		if id != "" {
			deps[id] = dependsOn
		}
		return nil

	}); err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}
	return deps, nil
}

// https://dart.dev/tools/pub/glossary#system-cache
func cacheDir() string {
	if dir := os.Getenv("PUB_CACHE"); dir != "" {
		return dir
	}

	// `%LOCALAPPDATA%\Pub\Cache` for Windows
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "Pub", "Cache")
	}

	// `~/.pub-cache` for Linux or Mac
	return filepath.Join(os.Getenv("HOME"), ".pub_cache")
}

type pubSpecYaml struct {
	Name         string         `yaml:"name"`
	Version      string         `yaml:"version,omitempty"`
	Dependencies map[string]any `yaml:"dependencies,omitempty"`
}

func parsePubSpecYaml(r io.Reader) (string, []string, error) {
	var spec pubSpecYaml
	if err := yaml.NewDecoder(r).Decode(&spec); err != nil {
		return "", nil, xerrors.Errorf("unable to decode: %w", err)
	}

	// Version is a required field only for packages from pub.dev:
	// https://dart.dev/tools/pub/pubspec#version
	// We can skip packages without version,
	// because we compare packages by ID (name+version)
	if spec.Version == "" || len(spec.Dependencies) == 0 {
		return "", nil, nil
	}

	// pubspec.yaml uses version ranges
	// save only dependencies names
	dependsOn := lo.Keys(spec.Dependencies)

	return dependency.ID(types.Pub, spec.Name, spec.Version), dependsOn, nil
}

func (a pubSpecLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.PubSpecLock
}

func (a pubSpecLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypePubSpecLock
}

func (a pubSpecLockAnalyzer) Version() int {
	return version
}
