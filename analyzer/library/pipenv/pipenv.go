package pipenv

import (
	"bytes"
	"path/filepath"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/utils"
	"github.com/knqyf263/go-dep-parser/pkg/pipenv"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&pipenvLibraryAnalyzer{})
}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
	libMap := map[analyzer.FilePath][]types.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := pipenv.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid Pipfile.lock format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a pipenvLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Pipfile.lock"}
}
