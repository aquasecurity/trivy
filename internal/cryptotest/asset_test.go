package cryptotest_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/crypto"
)

func TestAssets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		asset  func(...cryptotest.Option) crypto.Asset
		mutate func(*crypto.Asset)
	}{
		{
			name:  "certificate",
			asset: cryptotest.CertificateAsset,
			mutate: func(asset *crypto.Asset) {
				asset.Certificate.Subject = "changed"
			},
		},
		{
			name:  "public key",
			asset: cryptotest.PublicKeyAsset,
			mutate: func(asset *crypto.Asset) {
				asset.Key.Size = 4096
			},
		},
		{
			name:  "private key",
			asset: cryptotest.PrivateKeyAsset,
			mutate: func(asset *crypto.Asset) {
				asset.Key.Size = 4096
			},
		},
		{
			name:  "encrypted private key",
			asset: cryptotest.EncryptedPrivateKeyAsset,
			mutate: func(asset *crypto.Asset) {
				asset.Key.Size = 4096
			},
		},
		{
			name:  "algorithm",
			asset: cryptotest.AlgorithmAsset,
			mutate: func(asset *crypto.Asset) {
				asset.Algorithm.Family = "changed"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			first := tt.asset()
			second := tt.asset()
			require.NoError(t, first.Validate())
			require.NoError(t, second.Validate())
			assert.NotEmpty(t, first.FilePath)
			assert.Equal(t, first, second)

			mutated := tt.asset(cryptotest.WithMutate(tt.mutate))
			assert.NotEqual(t, first, mutated)

			tt.mutate(&first)
			assert.NotEqual(t, first, second)
		})
	}
}
