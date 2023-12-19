package composerjson

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/deepfactor-io/go-dep-parser/pkg/php/composerjson"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/language"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"golang.org/x/exp/slices"
)

func init() {
	analyzer.RegisterAnalyzer(&composerJSONAnalyzer{})
}

const (
	version = 1
)

// composerJSONAnalyzer analyzes 'composer.json'
type composerJSONAnalyzer struct{}

func (a composerJSONAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.Analyze(types.ComposerJSON, input.FilePath, input.Content, composerjson.NewParser())
}

func (a composerJSONAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if slices.Contains(strings.Split(filePath, "/"), "vendor") {
		return false
	}

	return filepath.Base(filePath) == types.ComposerJson
}

func (a composerJSONAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposerJSON
}

func (a composerJSONAnalyzer) Version() int {
	return version
}
