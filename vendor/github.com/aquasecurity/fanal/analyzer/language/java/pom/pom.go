package pom

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pomAnalyzer{})
}

const version = 1

// pomAnalyzer analyzes pom.xml
type pomAnalyzer struct{}

func (a pomAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := pom.NewParser(input.FilePath, pom.WithOffline(input.Options.Offline))

	return language.Analyze(types.Pom, input.FilePath, input.Content, p.Parse)
}

func (a pomAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == "pom.xml"
}

func (a pomAnalyzer) Type() analyzer.Type {
	return analyzer.TypePom
}

func (a pomAnalyzer) Version() int {
	return version
}
