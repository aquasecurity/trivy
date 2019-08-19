package pipenv

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
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
