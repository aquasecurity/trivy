package bundler

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/bundler"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&bundlerLibraryAnalyzer{})
}

type bundlerLibraryAnalyzer struct{}

func (a bundlerLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error) {
	libMap := map[types.FilePath][]godeptypes.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := bundler.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		libMap[types.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a bundlerLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Gemfile.lock"}
}

func (a bundlerLibraryAnalyzer) Name() string {
	return library.Bundler
}
