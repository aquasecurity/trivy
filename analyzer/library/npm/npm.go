package npm

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/npm"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&npmLibraryAnalyzer{})
}

type npmLibraryAnalyzer struct{}

func (a npmLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error) {
	libMap := map[types.FilePath][]godeptypes.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := npm.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		libMap[types.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a npmLibraryAnalyzer) RequiredFiles() []string {
	return []string{"package-lock.json"}
}

func (a npmLibraryAnalyzer) Name() string {
	return library.Npm
}
