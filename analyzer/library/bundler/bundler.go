package bundler

import (
	"bytes"
	"path/filepath"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/utils"
	"github.com/knqyf263/go-dep-parser/pkg/bundler"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&bundlerLibraryAnalyzer{})
}

type bundlerLibraryAnalyzer struct{}

func (a bundlerLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
	libMap := map[analyzer.FilePath][]types.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := bundler.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid Gemfile.lock format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a bundlerLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Gemfile.lock"}
}
