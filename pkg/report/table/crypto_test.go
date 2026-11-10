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
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Kind: ftypes.CryptoKindCertificate, Name: "CN=legacy.example.com"},
						FilePath:        "app/certs/legacy.pem",
					},
					{
						AssetID:         "curve",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Kind: ftypes.CryptoKindAlgorithm, Name: "EC-P-192"},
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
						RuleID:   "CRYPTO-0003",
						Title:    "Weak elliptic curve",
						Severity: "HIGH",
						AssetID:  "curve",
						Evidence: types.CryptoEvidence{Curve: "P-192", ClassicalSecurityLevel: new(96)},
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
Total: 4 (MEDIUM: 1, HIGH: 3)

┌──────────┬─────────────┬───────────────────────────────────┬──────────────────────┬──────────────────────────────────────────────────────┐
│ Severity │   Rule ID   │               Asset               │         File         │                       Message                        │
├──────────┼─────────────┼───────────────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ HIGH     │ CRYPTO-0002 │ RSA-1024 private key (PKCS#8)     │ app/certs/legacy.key │ RSA key is 1024 bits, less than 2048                 │
│          │             │                                   │                      │ https://avd.aquasec.com/crypto/crypto-0002/          │
│          │             ├───────────────────────────────────┼──────────────────────┤                                                      │
│          │             │ RSA-1024 public key (PKIX)        │ app/certs/legacy.pem │                                                      │
│          │             │                                   │                      │                                                      │
│          ├─────────────┼───────────────────────────────────┤                      ├──────────────────────────────────────────────────────┤
│          │ CRYPTO-0003 │ EC-P-192 algorithm                │                      │ Curve P-192 gives 96 bits of security, less than 112 │
│          │             │                                   │                      │ https://avd.aquasec.com/crypto/crypto-0003/          │
├──────────┼─────────────┼───────────────────────────────────┤                      ├──────────────────────────────────────────────────────┤
│ MEDIUM   │ CRYPTO-0004 │ CN=legacy.example.com certificate │                      │ Certificate expired on 2024-03-01                    │
│          │             │                                   │                      │ https://avd.aquasec.com/crypto/crypto-0004/          │
└──────────┴─────────────┴───────────────────────────────────┴──────────────────────┴──────────────────────────────────────────────────────┘
`,
		},
		{
			name: "group different assets that look the same",
			input: types.Result{
				Target: "example:latest",
				Class:  types.ClassCrypto,
				CryptoAssets: []ftypes.CryptoAsset{
					{
						AssetID:         "first",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "RSA-1024 public key"},
						FilePath:        "app/certs/keys.pem",
						Format:          ftypes.CryptoKeyFormatPKIX,
					},
					{
						AssetID:         "second",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "RSA-1024 public key"},
						FilePath:        "app/certs/keys.pem",
						Format:          ftypes.CryptoKeyFormatPKIX,
					},
				},
				CryptoFindings: []types.CryptoFinding{
					{
						RuleID:   "CRYPTO-0002",
						Severity: "HIGH",
						AssetID:  "first",
						Evidence: types.CryptoEvidence{KeySize: 1024},
					},
					{
						RuleID:   "CRYPTO-0002",
						Severity: "HIGH",
						AssetID:  "second",
						Evidence: types.CryptoEvidence{KeySize: 1024},
					},
				},
			},
			want: `
example:latest (crypto)
=======================
Total: 2 (MEDIUM: 0, HIGH: 2)

┌──────────┬─────────────┬───────────────────────────────┬────────────────────┬─────────────────────────────────────────────┐
│ Severity │   Rule ID   │             Asset             │        File        │                   Message                   │
├──────────┼─────────────┼───────────────────────────────┼────────────────────┼─────────────────────────────────────────────┤
│ HIGH     │ CRYPTO-0002 │ RSA-1024 public key (PKIX) x2 │ app/certs/keys.pem │ RSA key is 1024 bits, less than 2048        │
│          │             │                               │                    │ https://avd.aquasec.com/crypto/crypto-0002/ │
└──────────┴─────────────┴───────────────────────────────┴────────────────────┴─────────────────────────────────────────────┘
`,
		},
		{
			name: "do not group keys of different formats",
			input: types.Result{
				Target: "example:latest",
				Class:  types.ClassCrypto,
				CryptoAssets: []ftypes.CryptoAsset{
					{
						AssetID:         "pkix",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "RSA-1024 public key"},
						FilePath:        "app/certs/keys.pem",
						Format:          ftypes.CryptoKeyFormatPKIX,
					},
					{
						AssetID:         "pkcs1",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Name: "RSA-1024 public key"},
						FilePath:        "app/certs/keys.pem",
						Format:          ftypes.CryptoKeyFormatPKCS1,
					},
				},
				CryptoFindings: []types.CryptoFinding{
					{
						RuleID:   "CRYPTO-0002",
						Severity: "HIGH",
						AssetID:  "pkix",
						Evidence: types.CryptoEvidence{KeySize: 1024},
					},
					{
						RuleID:   "CRYPTO-0002",
						Severity: "HIGH",
						AssetID:  "pkcs1",
						Evidence: types.CryptoEvidence{KeySize: 1024},
					},
				},
			},
			want: `
example:latest (crypto)
=======================
Total: 2 (MEDIUM: 0, HIGH: 2)

┌──────────┬─────────────┬──────────────────────────────┬────────────────────┬─────────────────────────────────────────────┐
│ Severity │   Rule ID   │            Asset             │        File        │                   Message                   │
├──────────┼─────────────┼──────────────────────────────┼────────────────────┼─────────────────────────────────────────────┤
│ HIGH     │ CRYPTO-0002 │ RSA-1024 public key (PKCS#1) │ app/certs/keys.pem │ RSA key is 1024 bits, less than 2048        │
│          │             │                              │                    │ https://avd.aquasec.com/crypto/crypto-0002/ │
│          │             ├──────────────────────────────┤                    │                                             │
│          │             │ RSA-1024 public key (PKIX)   │                    │                                             │
│          │             │                              │                    │                                             │
└──────────┴─────────────┴──────────────────────────────┴────────────────────┴─────────────────────────────────────────────┘
`,
		},
		{
			name: "do not group certificates with different messages",
			input: types.Result{
				Target: "example:latest",
				Class:  types.ClassCrypto,
				CryptoAssets: []ftypes.CryptoAsset{
					{
						AssetID:         "old",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Kind: ftypes.CryptoKindCertificate, Name: "legacy.example.com"},
						FilePath:        "app/certs/chain.pem",
					},
					{
						AssetID:         "older",
						CryptoAssetInfo: ftypes.CryptoAssetInfo{Kind: ftypes.CryptoKindCertificate, Name: "legacy.example.com"},
						FilePath:        "app/certs/chain.pem",
					},
				},
				CryptoFindings: []types.CryptoFinding{
					{
						RuleID:   "CRYPTO-0004",
						Severity: "MEDIUM",
						AssetID:  "old",
						Evidence: types.CryptoEvidence{
							NotAfter: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					{
						RuleID:   "CRYPTO-0004",
						Severity: "MEDIUM",
						AssetID:  "older",
						Evidence: types.CryptoEvidence{
							NotAfter: time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC),
						},
					},
				},
			},
			want: `
example:latest (crypto)
=======================
Total: 2 (MEDIUM: 2, HIGH: 0)

┌──────────┬─────────────┬────────────────────────────────┬─────────────────────┬─────────────────────────────────────────────┐
│ Severity │   Rule ID   │             Asset              │        File         │                   Message                   │
├──────────┼─────────────┼────────────────────────────────┼─────────────────────┼─────────────────────────────────────────────┤
│ MEDIUM   │ CRYPTO-0004 │ legacy.example.com certificate │ app/certs/chain.pem │ Certificate expired on 2023-03-01           │
│          │             │                                │                     │ https://avd.aquasec.com/crypto/crypto-0004/ │
│          │             │                                │                     ├─────────────────────────────────────────────┤
│          │             │                                │                     │ Certificate expired on 2024-03-01           │
│          │             │                                │                     │ https://avd.aquasec.com/crypto/crypto-0004/ │
└──────────┴─────────────┴────────────────────────────────┴─────────────────────┴─────────────────────────────────────────────┘
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
