package gradle

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/gradle/lockfile"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeGradleLock, newGradleLockAnalyzer)
}

const (
	version        = 2
	fileNameSuffix = "gradle.lockfile"
)

// gradleLockAnalyzer analyzes '*gradle.lockfile'
type gradleLockAnalyzer struct {
	parser godeptypes.Parser
}

func newGradleLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gradleLockAnalyzer{
		parser: lockfile.NewParser(),
	}, nil
}

func (a gradleLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	poms, err := parsePoms()
	if err != nil {
		log.Logger.Warnf("Unable to get licenses: %s", err)
	}

	required := func(path string, d fs.DirEntry) bool {
		return a.Required(path, nil)
	}

	var apps []types.Application
	err = fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		var app *types.Application
		app, err = language.Parse(types.Gradle, path, r, a.parser)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}

		if app == nil {
			return nil
		}

		libs := lo.SliceToMap(app.Libraries, func(lib types.Package) (string, types.Package) {
			return lib.ID, lib
		})

		for i, lib := range app.Libraries {
			pom := poms[lib.ID]
			app.Libraries[i].Licenses = pom.Licenses.toStringArray()

			var deps []string
			for _, dep := range pom.Dependencies.Dependency {
				id := packageID(dep.GroupID, dep.ArtifactID, dep.Version)
				if _, ok := libs[id]; ok {
					deps = append(deps, id)
				}
			}
			app.Libraries[i].DependsOn = deps
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

func (a gradleLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, fileNameSuffix)
}

func (a gradleLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGradleLock
}

func (a gradleLockAnalyzer) Version() int {
	return version
}

func parsePoms() (map[string]pomXML, error) {
	// https://docs.gradle.org/current/userguide/directory_layout.html
	cacheDir := os.Getenv("GRADLE_USER_HOME")
	if cacheDir == "" {
		if runtime.GOOS == "windows" {
			cacheDir = filepath.Join(os.Getenv("%HOMEPATH%"), ".gradle")
		} else {
			cacheDir = filepath.Join(os.Getenv("HOME"), ".gradle")
		}
	}
	cacheDir = filepath.Join(cacheDir, "caches")

	if !fsutils.DirExists(cacheDir) {
		log.Logger.Warnf("Unable to get licanses. Gradle cache dir doesn't exist.")
		return nil, nil
	}

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Ext(path) == ".pom"
	}

	var poms = make(map[string]pomXML)
	err := fsutils.WalkDir(os.DirFS(cacheDir), ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		pom, err := parsePom(r)
		if err != nil {
			log.Logger.Debugf("Unable to get licenes for %q: %s", path, err)
		}

		// Skip if pom file doesn't contain licenses or dependencies
		if len(pom.Licenses.License) == 0 && len(pom.Dependencies.Dependency) == 0 {
			return nil
		}

		// If pom file doesn't contain GroupID or Version:
		// find these values from filepath
		// e.g. caches/modules-2/files-2.1/com.google.code.gson/gson/2.9.1/f0cf3edcef8dcb74d27cb427544a309eb718d772/gson-2.9.1.pom
		dirs := strings.Split(filepath.ToSlash(path), "/")
		if pom.GroupId == "" {
			pom.GroupId = dirs[len(dirs)-5]
		}
		if pom.Version == "" {
			pom.Version = dirs[len(dirs)-3]
		}

		for i, dep := range pom.Dependencies.Dependency {
			if strings.HasPrefix(dep.Version, "${") && strings.HasSuffix(dep.Version, "}") {
				dep.Version = strings.TrimPrefix(strings.TrimSuffix(dep.Version, "}"), "${")
				if resolvedVer, ok := pom.Properties[dep.Version]; ok {
					pom.Dependencies.Dependency[i].Version = resolvedVer
				} else if dep.Version == "${project.version}" {
					pom.Dependencies.Dependency[i].Version = dep.Version
				} else {
					// We use simplified logic to resolve properties.
					// If necessary, update and use the logic for maven pom's
					log.Logger.Warnf("Unable to resolve version for %q. Please open a new discussion to update the Trivy logic.", path)
				}
			}
		}

		poms[packageID(pom.GroupId, pom.ArtifactId, pom.Version)] = pom
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("gradle licenses walk error: %w", err)
	}

	return poms, nil
}
