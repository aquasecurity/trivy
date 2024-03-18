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
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/dart/pub"
	godeptypes "github.com/aquasecurity/trivy/pkg/dependency/types"
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
	parser godeptypes.Parser
}

func newPubSpecLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pubSpecLockAnalyzer{
		parser: pub.NewParser(),
	}, nil
}

func (a pubSpecLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	// get all DependsOn from cache dir
	// lib ID -> DependsOn names
	allDependsOn, err := findDependsOn()
	if err != nil {
		log.Logger.Warnf("Unable to parse cache dir: %s", err)
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
			libs := lo.SliceToMap(app.Libraries, func(lib types.Package) (string, string) {
				return lib.Name, lib.ID
			})

			for i, lib := range app.Libraries {
				var dependsOn []string
				for _, depName := range allDependsOn[lib.ID] {
					if depID, ok := libs[depName]; ok {
						dependsOn = append(dependsOn, depID)
					}
				}
				app.Libraries[i].DependsOn = dependsOn
			}
		}

		sort.Sort(app.Libraries)
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

func findDependsOn() (map[string][]string, error) {
	dir := cacheDir()
	if !fsutils.DirExists(dir) {
		log.Logger.Debugf("Cache dir (%s) not found. Need 'dart pub get' to fill dependency relationships", dir)
		return nil, nil
	}

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == pubSpecYamlFileName
	}

	deps := make(map[string][]string)
	if err := fsutils.WalkDir(os.DirFS(dir), ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		id, dependsOn, err := parsePubSpecYaml(r)
		if err != nil {
			log.Logger.Debugf("Unable to parse %q: %s", path, err)
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
	Name         string                 `yaml:"name"`
	Version      string                 `yaml:"version,omitempty"`
	Dependencies map[string]interface{} `yaml:"dependencies,omitempty"`
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
	dependsOn := maps.Keys(spec.Dependencies)

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
