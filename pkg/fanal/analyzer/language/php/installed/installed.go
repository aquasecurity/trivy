package installed

import (
	"context"
	"os"
	"path/filepath"

	"github.com/deepfactor-io/go-dep-parser/pkg/php/composer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/language"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&composerInstalledAnalyzer{})
}

const (
	version = 1
)

// composerInstalledAnalyzer analyzes 'installed.json'
type composerInstalledAnalyzer struct{}

func (a composerInstalledAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.Analyze(types.ComposerInstalled, input.FilePath, input.Content, composer.NewParser())
}

func (a composerInstalledAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.ComposerInstalledJson
}

func (a composerInstalledAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposerInstalled
}

func (a composerInstalledAnalyzer) Version() int {
	return version
}
