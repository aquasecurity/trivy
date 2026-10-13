package table_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestCryptoRenderer(t *testing.T) {
	tests := []struct {
		name  string
		input types.Result
		want  string
	}{
		{
			name: "findings",
			input: types.Result{
				Target: "example:latest",
				Class:  types.ClassCrypto,
				CryptoAssets: []ftypes.CryptoAsset{
					{
						AssetID:         "cert",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "CN=legacy.example.com"},
						FilePath:        "app/certs/legacy.pem",
					},
					{
						AssetID:         "public",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "RSA-1024 public key"},
						FilePath:        "app/certs/legacy.pem",
						Format:          ftypes.CryptoKeyFormatPKIX,
					},
					{
						AssetID:         "private",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "RSA-1024 private key"},
						FilePath:        "app/certs/legacy.key",
						Format:          ftypes.CryptoKeyFormatPKCS8,
					},
				},
				CryptoFindings: []types.CryptoFinding{
					{
						RuleID:   "CRYPTO-0004",
						Title:    "Expired certificate",
						Severity: "MEDIUM",
						AssetID:  "cert",
						Evidence: types.CryptoEvidence{
							NotAfter: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					{
						RuleID:   "CRYPTO-0002",
						Title:    "Small RSA key",
						Severity: "HIGH",
						AssetID:  "public",
						Evidence: types.CryptoEvidence{KeySize: 1024},
					},
					{
						RuleID:   "CRYPTO-0002",
						Title:    "Small RSA key",
						Severity: "HIGH",
						AssetID:  "private",
						Evidence: types.CryptoEvidence{KeySize: 1024},
					},
				},
			},
			want: `
example:latest (crypto)
=======================
Total: 3 (MEDIUM: 1, HIGH: 2)

┌──────────┬─────────────┬───────────────────────────────┬──────────────────────┬───────────────────────┐
│ Severity │   Rule ID   │             Asset             │         File         │        Details        │
├──────────┼─────────────┼───────────────────────────────┼──────────────────────┼───────────────────────┤
│ HIGH     │ CRYPTO-0002 │ RSA-1024 private key (PKCS#8) │ app/certs/legacy.key │ 1024 bits             │
│          │             ├───────────────────────────────┼──────────────────────┤                       │
│          │             │ RSA-1024 public key (PKIX)    │ app/certs/legacy.pem │                       │
├──────────┼─────────────┼───────────────────────────────┤                      ├───────────────────────┤
│ MEDIUM   │ CRYPTO-0004 │ CN=legacy.example.com         │                      │ expired on 2024-03-01 │
└──────────┴─────────────┴───────────────────────────────┴──────────────────────┴───────────────────────┘
`,
		},
		{
			name: "no findings",
			input: types.Result{
				Target: "example:latest",
				Class:  types.ClassCrypto,
				CryptoAssets: []ftypes.CryptoAsset{
					{
						CryptoAssetInfo: ftypes.CryptoAssetInfo{
							Kind: ftypes.CryptoKindCertificate,
						},
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			renderer := table.NewCryptoRenderer(buf, false, []dbTypes.Severity{
				dbTypes.SeverityHigh,
				dbTypes.SeverityMedium,
			})
			renderer.Render(tt.input)
			assert.Equal(t, tt.want, buf.String())
		})
	}
}
