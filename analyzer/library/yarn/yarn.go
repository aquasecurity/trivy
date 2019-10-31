package yarn

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/yarn"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&yarnLibraryAnalyzer{})
}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
	libMap := map[analyzer.FilePath][]types.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {

		basename := filepath.Base(filename)

		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := yarn.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid yarn.lock format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}

	return libMap, nil
}

func (a yarnLibraryAnalyzer) RequiredFiles() []string {
	return []string{"yarn.lock"}
}
