package executable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&executableAnalyzer{})
}

const version = 1

// executableAnalyzer calculates SHA-256 for each binary not managed by package managers (called unpackaged binaries)
// so that it can search for SBOM attestation in post-handler.
type executableAnalyzer struct{}

func (a executableAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Skip non-binaries
	isBinary, err := utils.IsBinary(input.Content, input.Info.Size())
	if !isBinary || err != nil {
		return nil, nil
	}

	h := sha256.New()
	if _, err = io.Copy(h, input.Content); err != nil {
		return nil, xerrors.Errorf("sha256 error: %w", err)
	}
	s := hex.EncodeToString(h.Sum(nil))

	return &analyzer.AnalysisResult{
		Digests: map[string]string{
			input.FilePath: "sha256:" + s,
		},
	}, nil
}

func (a executableAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return utils.IsExecutable(fileInfo)
}

func (a executableAnalyzer) Type() analyzer.Type {
	return analyzer.TypeExecutable
}

func (a executableAnalyzer) Version() int {
	return version
}
