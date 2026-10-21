package types_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestResults_DropCryptoFindings(t *testing.T) {
	assets := []ftypes.CryptoAsset{
		{
			AssetID: "1e7b3d9c04a65f28",
			CryptoAssetInfo: ftypes.CryptoAssetInfo{
				Kind: ftypes.CryptoKindCertificate,
			},
		},
	}

	tests := []struct {
		name    string
		results types.Results
		want    types.Results
	}{
		{
			name: "findings",
			results: types.Results{
				{
					Class:        types.ClassCrypto,
					CryptoAssets: assets,
					CryptoFindings: []types.CryptoFinding{
						{
							RuleID:   "CRYPTO-0004",
							Severity: "MEDIUM",
							AssetID:  "1e7b3d9c04a65f28",
						},
					},
				},
			},
			want: types.Results{
				{
					Class:        types.ClassCrypto,
					CryptoAssets: assets,
				},
			},
		},
		{
			name: "no findings",
			results: types.Results{
				{
					Class:        types.ClassCrypto,
					CryptoAssets: assets,
				},
			},
			want: types.Results{
				{
					Class:        types.ClassCrypto,
					CryptoAssets: assets,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.results.DropCryptoFindings()
			assert.Equal(t, tt.want, tt.results)
		})
	}
}
