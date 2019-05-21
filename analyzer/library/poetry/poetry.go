package poetry

import (
	"bytes"
	"path/filepath"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/utils"
	"github.com/knqyf263/go-dep-parser/pkg/poetry"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&poetryLibraryAnalyzer{})
}

type poetryLibraryAnalyzer struct{}

func (a poetryLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
	libMap := map[analyzer.FilePath][]types.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := poetry.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid poetry.lock format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a poetryLibraryAnalyzer) RequiredFiles() []string {
	return []string{"poetry.lock"}
}
