package composer

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
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&composerLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{types.ComposerLock}

type composerLibraryAnalyzer struct{}

func (a composerLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// we should skip `composer.lock` inside `vendor` folder
	if sep := string(os.PathSeparator); strings.Contains(input.FilePath, "vendor"+sep) {
		file := filepath.Base(input.FilePath)
		subDirs := strings.Split(input.FilePath, sep)
		for i, s := range subDirs {
			if s == "vendor" {
				path := filepath.Join(subDirs[:i]...)
				f := filepath.Join(path, file)
				if _, err := os.Stat(f); err == os.ErrNotExist {
					continue
				}
				return nil, nil
			}
		}
	}
	res, err := language.Analyze(types.Composer, input.FilePath, input.Content, composer.NewParser())

	if err != nil {
		return nil, xerrors.Errorf("error with composer.lock: %w", err)
	}
	return res, nil
}

func (a composerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a composerLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposer
}

func (a composerLibraryAnalyzer) Version() int {
	return version
}
