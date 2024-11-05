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

const version = 1

// pomAnalyzer analyzes pom.xml
type pomAnalyzer struct{}

func (a pomAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	filePath := filepath.Join(input.Dir, input.FilePath)
	p := pom.NewParser(filePath, pom.WithOffline(input.Options.Offline))
	res, err := language.Analyze(types.Pom, input.FilePath, input.Content, p)
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
