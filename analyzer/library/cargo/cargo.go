package cargo

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/cargo"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&cargoLibraryAnalyzer{})
}

type cargoLibraryAnalyzer struct{}

func (a cargoLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error) {
	libMap := map[types.FilePath][]godeptypes.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := cargo.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		libMap[types.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a cargoLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Cargo.lock"}
}

func (a cargoLibraryAnalyzer) Name() string {
	return library.Cargo
}
