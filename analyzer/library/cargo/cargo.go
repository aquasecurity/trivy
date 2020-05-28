package cargo

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/cargo"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&cargoLibraryAnalyzer{})
}

var requiredFiles = []string{"Cargo.lock"}

type cargoLibraryAnalyzer struct{}

func (a cargoLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	ret, err := library.Analyze(content, cargo.Parse)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with Cargo.lock: %w", err)
	}
	return ret, nil
}

func (a cargoLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a cargoLibraryAnalyzer) Name() string {
	return library.Cargo
}
