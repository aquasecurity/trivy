package crypto

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/crypto"
	"github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

func init() {
	analyzer.RegisterAnalyzer(&cryptoAnalyzer{})
}

const version = 1

var requiredExtensions = set.NewCaseInsensitive(".pem", ".der", ".crt", ".cer", ".key")

// cryptoAnalyzer inventories cryptographic assets. It holds no format knowledge: the
// parsers describe the formats and the extractor describes the assets.
type cryptoAnalyzer struct{}

func (a *cryptoAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	logger := log.WithPrefix(log.PrefixCrypto).With(log.FilePath(input.FilePath))

	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read %s: %w", input.FilePath, err)
	}

	var assets []ftypes.CryptoAsset
	for _, object := range x509.Parse(ctx, input.FilePath, content) {
		extracted := crypto.Extract(object)
		// The assets of one object are validated as a group and dropped as a group, because
		// their relationships refer to one another.
		if err := validate(extracted); err != nil {
			logger.Warn("Invalid cryptographic asset", log.Err(err))
			continue
		}
		assets = append(assets, extracted...)
	}

	// A file can describe the same asset more than once: every certificate in a bundle is
	// signed with the same algorithm, and an Ed25519 certificate uses one OID for both its
	// signature and its key.
	assets = dedupe(assets)
	if len(assets) == 0 {
		return nil, nil
	}

	for i := range assets {
		assets[i].FilePath = input.FilePath
	}
	return &analyzer.AnalysisResult{CryptoAssets: assets}, nil
}

// validate reports the first asset that breaks the model invariants.
func validate(assets []ftypes.CryptoAsset) error {
	for i := range assets {
		if err := assets[i].Validate(); err != nil {
			return xerrors.Errorf("asset %q: %w", assets[i].Name, err)
		}
	}
	return nil
}

// dedupe collapses assets that share an identity, keeping the first description of each.
func dedupe(assets []ftypes.CryptoAsset) []ftypes.CryptoAsset {
	// The slice keeps the order the assets were extracted in; the map holds their positions.
	deduped := make([]ftypes.CryptoAsset, 0, len(assets))
	indexes := make(map[ftypes.CryptoDescriptor]int, len(assets))
	for _, asset := range assets {
		descriptor := asset.Descriptor()
		index, seen := indexes[descriptor]
		if !seen {
			indexes[descriptor] = len(deduped)
			deduped = append(deduped, asset)
			continue
		}
		// A key in a container of its own wins over the same key taken from a certificate,
		// because only it carries the format and the encoding.
		kept := deduped[index]
		if asset.Key != nil && kept.Key != nil && asset.Key.Format != "" && kept.Key.Format == "" {
			deduped[index] = asset
		}
	}
	return deduped
}

// Required selects a file by extension, without reading its content.
func (a *cryptoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return requiredExtensions.Contains(filepath.Ext(filePath))
}

func (a *cryptoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCrypto
}

func (a *cryptoAnalyzer) Version() int {
	return version
}
