package types_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestResults_Failed(t *testing.T) {
	tests := []struct {
		name    string
		results types.Results
		want    bool
	}{
		{
			name: "crypto findings",
			results: types.Results{
				{
					Class: types.ClassCrypto,
					CryptoFindings: []types.CryptoFinding{
						{
							RuleID:   "crypto-rsa-key-below-2048",
							Severity: "HIGH",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "crypto assets without findings",
			results: types.Results{
				{
					Class: types.ClassCrypto,
					CryptoAssets: []ftypes.CryptoAsset{
						{
							Kind: ftypes.CryptoKindAlgorithm,
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.results.Failed())
		})
	}
}
