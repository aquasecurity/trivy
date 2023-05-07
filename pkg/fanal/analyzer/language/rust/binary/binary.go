package binary

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/rust/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&rustBinaryLibraryAnalyzer{})
}

const version = 1

type rustBinaryLibraryAnalyzer struct{}

func (a rustBinaryLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.RustBinary, input.FilePath, input.Content, binary.NewParser())
	if errors.Is(err, binary.ErrUnrecognizedExe) || errors.Is(err, binary.ErrNonRustBinary) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("rust binary parse error: %w", err)
	}
	return res, nil
}

func (a rustBinaryLibraryAnalyzer) Required(filePath string, fileInfo os.FileInfo) bool {
	// Bitnami images have SBOMs inside, so there is no need to analyze Rust binaries.
	if strings.HasPrefix(filePath, "opt/bitnami") {
		return false
	}
	return utils.IsExecutable(fileInfo)
}

func (a rustBinaryLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRustBinary
}

func (a rustBinaryLibraryAnalyzer) Version() int {
	return version
}
