package composer

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/php/composer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&composerVendorAnalyzer{})
}

const (
	composerInstalledAnalyzerVersion = 1
)

// composerVendorAnalyzer analyzes 'installed.json'
type composerVendorAnalyzer struct{}

func (a composerVendorAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.Analyze(types.ComposerVendor, input.FilePath, input.Content, composer.NewParser())
}

func (a composerVendorAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.ComposerInstalledJson
}

func (a composerVendorAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposerVendor
}

func (a composerVendorAnalyzer) Version() int {
	return composerInstalledAnalyzerVersion
}
