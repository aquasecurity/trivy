package pipenv

import (
	"bytes"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&pipenvLibraryAnalyzer{})
}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error) {
	libMap := map[types.FilePath][]godeptypes.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := pipenv.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		libMap[types.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a pipenvLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Pipfile.lock"}
}

func (a pipenvLibraryAnalyzer) Name() string {
	return library.Pipenv
}
