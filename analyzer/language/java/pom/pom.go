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

func (a pomAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	// TODO: support offline mode
	p := pom.NewParser(target.FilePath)

	return language.Analyze(types.Pom, target.FilePath, target.Content, p.Parse)
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
