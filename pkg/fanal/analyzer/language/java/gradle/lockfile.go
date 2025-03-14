package gradle

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/gradle/lockfile"
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
	logger *log.Logger
	parser language.Parser
}

func newGradleLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gradleLockAnalyzer{
		logger: log.WithPrefix("gradle"),
		parser: lockfile.NewParser(),
	}, nil
}

func (a gradleLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	poms, err := a.parsePoms()
	if err != nil {
		a.logger.Warn("Unable to get licenses and dependencies", log.Err(err))
	}

	required := func(path string, d fs.DirEntry) bool {
		// Parse all required files: `*gradle.lockfile` (from a.Required func) + input.FilePatterns.Match()
		return true
	}

	var apps []types.Application
	err = fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		var app *types.Application
		app, err = language.Parse(types.Gradle, filePath, r, a.parser)
		if err != nil {
			return xerrors.Errorf("%s parse error: %w", filePath, err)
		}

		if app == nil {
			return nil
		}

		pkgs := lo.SliceToMap(app.Packages, func(lib types.Package) (string, struct{}) {
			return lib.ID, struct{}{}
		})

		for i, lib := range app.Packages {
			pom := poms[lib.ID]

			// Fill licenses from pom file
			if len(pom.Licenses.License) > 0 {
				app.Packages[i].Licenses = lo.Map(pom.Licenses.License, func(license License, _ int) string {
					return license.Name
				})
			}

			// File child deps from pom file
			var deps []string
			for _, dep := range pom.Dependencies.Dependency {
				id := packageID(dep.GroupID, dep.ArtifactID, dep.Version)
				if _, ok := pkgs[id]; ok {
					deps = append(deps, id)
				}
			}
			sort.Strings(deps)
			app.Packages[i].DependsOn = deps
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

func (a gradleLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, fileNameSuffix)
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
