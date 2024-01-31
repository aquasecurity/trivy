package pom

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"
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
	p := pom.NewParser(filepath.Join(input.Dir, input.FilePath), pom.WithOffline(input.Options.Offline))
	res, err := language.Analyze(types.Pom, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
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
