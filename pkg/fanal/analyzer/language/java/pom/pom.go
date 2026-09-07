package pom

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/pom"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pomAnalyzer{})
}

const version = 2

// pomAnalyzer analyzes pom.xml
type pomAnalyzer struct{}

func (a pomAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	filePath := filepath.Join(input.Dir, input.FilePath)
	p := pom.NewParser(filePath,
		pom.WithOffline(input.Options.Offline),
		pom.WithConfigFileMirrors(input.Options.MavenMirrors),
	)
	res, err := language.Analyze(ctx, types.Pom, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}

	// Mark integration test pom files for `maven-invoker-plugin` as Dev to skip them by default.
	if isIntegrationTestDir(filePath) && res != nil {
		for i := range res.Applications {
			for j := range res.Applications[i].Packages {
				res.Applications[i].Packages[j].Dev = true
			}
		}
	}

	// A pom.xml under META-INF/maven/<groupId>/<artifactId>/ is the copy that maven-archiver
	// embeds into a built artifact. It describes what the artifact was compiled against, not
	// what ships next to it: test, provided and optional dependencies are listed just the same,
	// and none of them is necessarily present. When such an artifact is scanned in exploded form
	// (an unpacked fat JAR, an exploded WAR, a JAR unzipped in a Dockerfile) the file is visible
	// to this analyzer, and treating it as a project manifest reports every declared dependency
	// as installed. Keep the artifact itself -- it is what was unpacked -- and mark the declared
	// dependencies as Dev so they are skipped by default but still reachable with
	// --include-dev-deps.
	if isEmbeddedArchivePom(filePath) && res != nil {
		for i := range res.Applications {
			for j := range res.Applications[i].Packages {
				if res.Applications[i].Packages[j].Relationship == types.RelationshipRoot {
					continue
				}
				res.Applications[i].Packages[j].Dev = true
			}
		}
	}

	return res, nil
}

func (a pomAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.MavenPom
}

func (a pomAnalyzer) Type() analyzer.Type {
	return analyzer.TypePom
}

func (a pomAnalyzer) Version() int {
	return version
}

// isEmbeddedArchivePom checks that the pom file is the copy maven-archiver embeds into a built artifact.
// https://maven.apache.org/shared/maven-archiver/#pom-properties-content
func isEmbeddedArchivePom(filePath string) bool {
	dirs := strings.Split(filepath.ToSlash(filePath), "/")
	// filepath pattern: `**/META-INF/maven/<groupId>/<artifactId>/pom.xml`
	if len(dirs) < 5 {
		return false
	}
	return dirs[len(dirs)-5] == "META-INF" && dirs[len(dirs)-4] == "maven"
}

// isIntegrationTestDir checks that pom file is in directory with integration tests of `maven-invoker-plugin`
// https://maven.apache.org/plugins/maven-invoker-plugin/usage.html
func isIntegrationTestDir(filePath string) bool {
	dirs := strings.Split(filepath.ToSlash(filePath), "/")
	// filepath pattern: `**/[src|target]/it/*/pom.xml`
	if len(dirs) < 4 {
		return false
	}
	return (dirs[len(dirs)-4] == "src" || dirs[len(dirs)-4] == "target") && dirs[len(dirs)-3] == "it"
}
