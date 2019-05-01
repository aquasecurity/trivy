package composer

import (
	"bytes"
	"path/filepath"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/utils"
	"github.com/knqyf263/go-dep-parser/pkg/composer"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&composerLibraryAnalyzer{})
}

type composerLibraryAnalyzer struct{}

func (a composerLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
	libMap := map[analyzer.FilePath][]types.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := composer.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid composer.lock format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a composerLibraryAnalyzer) RequiredFiles() []string {
	return []string{"composer.lock"}
}
