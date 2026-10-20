package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestAssignIDs(t *testing.T) {
	base := cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(asset *ftypes.CryptoAsset) {
		asset.Layer = ftypes.Layer{DiffID: "sha256:9a4f"}
	}))

	tests := []struct {
		name   string
		mutate func(*ftypes.CryptoAsset)
		same   bool
	}{
		{
			name:   "same asset",
			mutate: func(*ftypes.CryptoAsset) {},
			same:   true,
		},
		{
			name: "different name and encoding",
			mutate: func(asset *ftypes.CryptoAsset) {
				asset.Name = "RSA-2048 public key"
				asset.Encoding = ftypes.CryptoEncodingDER
			},
			same: true,
		},
		{
			name: "different identity",
			mutate: func(asset *ftypes.CryptoAsset) {
				asset.Identity.Value = "4f1c"
			},
		},
		{
			name: "different file path",
			mutate: func(asset *ftypes.CryptoAsset) {
				asset.FilePath = "/etc/other.pem"
			},
		},
		{
			name: "same file in a different layer",
			mutate: func(asset *ftypes.CryptoAsset) {
				asset.Layer.DiffID = "sha256:3c1d"
			},
			same: true,
		},
		{
			name: "key without a container of its own",
			mutate: func(asset *ftypes.CryptoAsset) {
				asset.Format = ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(asset *ftypes.CryptoAsset) {
				asset.Layer = base.Layer
				tt.mutate(asset)
			}))
			assets := []ftypes.CryptoAsset{base, other}
			crypto.AssignIDs(assets)
			assert.NotEmpty(t, assets[0].AssetID)
			assert.Equal(t, tt.same, assets[0].AssetID == assets[1].AssetID)
		})
	}
}
