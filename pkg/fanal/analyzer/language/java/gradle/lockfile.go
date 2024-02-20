package gradle

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/gradle/lockfile"
	godeptypes "github.com/aquasecurity/trivy/pkg/dependency/parser/types"
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
	buildGradle    = "build.gradle"
	buildGradleKts = "build.gradle.kts"
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
		return strings.HasSuffix(path, fileNameSuffix)
	}

	var apps []types.Application
	err = fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		var app *types.Application
		app, err = language.Parse(types.Gradle, filePath, r, a.parser)
		if err != nil {

		}

		if app == nil {
			return nil
		}

		var directDeps []string
		var buildGradleFound bool
		directDeps, buildGradleFound, err = parseBuildGradle(input.FS, path.Dir(filePath))
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", filePath, err)
		}

		libs := lo.SliceToMap(app.Libraries, func(lib types.Package) (string, types.Package) {
			return lib.ID, lib
		})

		for i, lib := range app.Libraries {
			if buildGradleFound {
				app.Libraries[i].Indirect = true
				if slices.Contains(directDeps, lib.ID) {
					app.Libraries[i].Indirect = false
				}
			}

			pom := poms[lib.ID]

			if len(pom.Licenses.License) > 0 {
				app.Libraries[i].Licenses = lo.Map(pom.Licenses.License, func(license License, _ int) string {
					return license.Name
				})
			}

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
	return strings.HasSuffix(filePath, fileNameSuffix) || filepath.Base(filePath) == buildGradle || filepath.Base(filePath) == buildGradleKts
}

func (a gradleLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGradleLock
}

func (a gradleLockAnalyzer) Version() int {
	return version
}

func packageID(groupId, artifactId, ver string) string {
	return fmt.Sprintf("%s:%s:%s", groupId, artifactId, ver)
}
