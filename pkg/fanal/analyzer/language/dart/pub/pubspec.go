package pub

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-dep-parser/pkg/dart/pub"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
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
	// `lib_ID` -> `lib_names`
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

		// Required to search for library versions from DependsOn.
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

	deps := make(map[string][]string)
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() {
			return nil
		}
		// parse only `pubspec.yaml` files
		if path.Base(p) != pubSpecYamlFileName {
			return nil
		}

		id, dependsOn, err := parsePubSpecYaml(p)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %s", p, err)
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
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Dependencies map[string]string `yaml:"dependencies,omitempty"`
}

func parsePubSpecYaml(filePath string) (string, []string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", nil, xerrors.Errorf("unable to open %q to get list of direct deps: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()

	var spec pubSpecYaml
	if err = yaml.NewDecoder(f).Decode(&spec); err != nil {
		return "", nil, xerrors.Errorf("unable to decode %q: %w", filePath, err)
	}
	if len(spec.Dependencies) > 0 {
		// pubspec.yaml uses version ranges
		// save only dependencies names
		dependsOn := lo.MapToSlice(spec.Dependencies, func(key string, _ string) string {
			return key
		})
		return utils.PackageID(spec.Name, spec.Version), dependsOn, nil
	}
	return "", nil, nil
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
