package installed

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/php/composer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
	p := composer.NewParser()
	res, err := language.Analyze(types.Composer, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}
	return res, nil
}

func (a composerInstalledAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// installed.json has `path_to_app/vendor/composer/installed.json` file path
	dir, fileName := filepath.Split(filePath)
	return strings.HasSuffix(dir, "vendor/composer/") && fileName == types.ComposerInstalled
}

func (a composerInstalledAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposerInstalled
}

func (a composerInstalledAnalyzer) Version() int {
	return version
}
