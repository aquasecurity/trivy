package crypto

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

func init() {
	analyzer.RegisterAnalyzer(&cryptoAnalyzer{})
}

const (
	version = 1

	// maxFileSize bounds what is read into memory. Cryptographic material stays far below
	// it — the largest trust store is a few hundred kilobytes — while the eligible
	// extensions are shared with unrelated formats, such as Keynote presentations.
	maxFileSize = 10 << 20 // 10MB
)

var requiredExtensions = set.NewCaseInsensitive(".pem", ".der", ".crt", ".cer", ".key")

// cryptoAnalyzer inventories cryptographic assets. It holds no format knowledge, leaving
// that to the parsers.
type cryptoAnalyzer struct{}

func (a *cryptoAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read %s: %w", input.FilePath, err)
	}

	assets, err := x509.Parse(ctx, input.FilePath, content)
	if err != nil {
		return nil, xerrors.Errorf("parse %s: %w", input.FilePath, err)
	}

	// A file can describe the same asset more than once. Every certificate in a bundle is
	// signed with the same algorithm, and an Ed25519 certificate uses one OID for both its
	// signature and its key.
	assets = ftypes.DedupeCryptoAssets(assets)
	if len(assets) == 0 {
		return nil, nil
	}
	return &analyzer.AnalysisResult{CryptoAssets: assets}, nil
}

// Required selects a file by extension and size, without reading its content.
func (a *cryptoAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if info != nil && info.Size() > maxFileSize {
		return false
	}
	return requiredExtensions.Contains(filepath.Ext(filePath))
}

func (a *cryptoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCrypto
}

func (a *cryptoAnalyzer) Version() int {
	return version
}
