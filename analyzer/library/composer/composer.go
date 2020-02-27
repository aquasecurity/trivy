package composer

import (
	"bytes"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/composer"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&composerLibraryAnalyzer{})
}

type composerLibraryAnalyzer struct{}

func (a composerLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error) {
	libMap := map[types.FilePath][]godeptypes.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := composer.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		libMap[types.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a composerLibraryAnalyzer) RequiredFiles() []string {
	return []string{"composer.lock"}
}

func (a composerLibraryAnalyzer) Name() string {
	return library.Composer
}
