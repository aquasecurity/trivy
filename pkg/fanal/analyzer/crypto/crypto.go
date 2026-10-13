package crypto

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/pkcs12"
	"github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&cryptoAnalyzer{})
}

const (
	version = 3

	// maxFileSize bounds what is read into memory. The eligible extensions are shared with
	// unrelated formats, such as Keynote presentations, which grow far beyond any file of
	// cryptographic material.
	maxFileSize = 10 << 20 // 10MB
)

var (
	requiredExtensions = set.NewCaseInsensitive(".pem", ".der", ".crt", ".cer", ".key")

	keystoreExtensions = set.NewCaseInsensitive(".p12", ".pfx", ".jks", ".keystore")

	// jksMagics are the leading bytes of the JKS and JCEKS formats.
	jksMagics = [][]byte{
		{0xFE, 0xED, 0xFE, 0xED},
		{0xCE, 0xCE, 0xCE, 0xCE},
	}
)

// javaTrustStore is the file name of the Java trust store, which is JKS before JDK 18
// and PKCS#12 since.
const javaTrustStore = "cacerts"

// cryptoAnalyzer inventories cryptographic assets.
type cryptoAnalyzer struct{}

func (a *cryptoAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// A file matched by --file-patterns reaches the analyzer without passing Required.
	content, err := xio.ReadAllWithLimit(input.Content, maxFileSize)
	if errors.Is(err, xio.ErrLimitExceeded) {
		logSkippedFile(input.FilePath)
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("read %s: %w", input.FilePath, err)
	}

	var assets []types.CryptoAsset
	if isKeystore(input.FilePath) {
		assets, err = parseKeystore(ctx, input.FilePath, content)
	} else {
		assets, err = x509.Parse(ctx, input.FilePath, content)
	}
	if err != nil {
		return nil, xerrors.Errorf("parse %s: %w", input.FilePath, err)
	}
	if len(assets) == 0 {
		return nil, nil
	}
	return &analyzer.AnalysisResult{CryptoAssets: assets}, nil
}

// Required selects a file by extension and size, without reading its content.
func (a *cryptoAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if !requiredExtensions.Contains(filepath.Ext(filePath)) && !isKeystore(filePath) {
		return false
	}
	if info.Size() > maxFileSize {
		logSkippedFile(filePath)
		return false
	}
	return true
}

func isKeystore(filePath string) bool {
	return keystoreExtensions.Contains(filepath.Ext(filePath)) || filepath.Base(filePath) == javaTrustStore
}

func parseKeystore(ctx context.Context, filePath string, content []byte) ([]types.CryptoAsset, error) {
	// keytool writes PKCS#12 by default since JDK 9, even to .jks and .keystore files.
	for _, magic := range jksMagics {
		if bytes.HasPrefix(content, magic) {
			log.WithPrefix("crypto").Debug("Java keystore format is not supported", log.FilePath(filePath))
			return nil, nil
		}
	}
	return pkcs12.Parse(ctx, filePath, content)
}

// logSkippedFile reports a file left out of the inventory for its size.
func logSkippedFile(filePath string) {
	log.WithPrefix("crypto").Debug("File is too large to read", log.FilePath(filePath))
}

func (a *cryptoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCrypto
}

func (a *cryptoAnalyzer) Version() int {
	return version
}
