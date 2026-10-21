package check_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/crypto"
	"github.com/aquasecurity/trivy/pkg/crypto/check"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	layer = ftypes.Layer{
		Digest: "sha256:3c1d",
		DiffID: "sha256:9a4f",
	}
)

func algorithmDescriptor(oid, parameters string) ftypes.CryptoDescriptor {
	return ftypes.CryptoDescriptor{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      oid,
			Parameters: parameters,
		},
	}
}

// withID sets the ID the scan assigns to the asset.
func withID(asset ftypes.CryptoAsset) ftypes.CryptoAsset {
	assets := []ftypes.CryptoAsset{asset}
	crypto.AssignIDs(assets)
	return assets[0]
}

func certificate(filePath, signatureOID string, notAfter time.Time) ftypes.CryptoAsset {
	return withID(ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind: ftypes.CryptoKindCertificate,
			Identity: ftypes.CryptoIdentity{
				Method: ftypes.CryptoMethodSHA256,
				Value:  "5e0b",
			},
			Name: "CN=legacy.example.com",
			Certificate: &ftypes.CryptoCertificate{
				Subject:  "CN=legacy.example.com",
				NotAfter: notAfter,
				Format:   ftypes.CryptoCertificateFormatX509,
			},
			Relationships: []ftypes.CryptoRelationship{{
				Type:         ftypes.CryptoRelationshipSignedWith,
				RelatedAsset: algorithmDescriptor(signatureOID, ""),
			}},
		},
		FilePath: filePath,
		Encoding: ftypes.CryptoEncodingPEM,
		Layer:    layer,
	})
}

func publicKey(filePath, algorithmOID string, size int, format ftypes.CryptoKeyFormat) ftypes.CryptoAsset {
	return withID(ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind:    ftypes.CryptoKindKey,
			KeyType: ftypes.CryptoKeyTypePublic,
			Identity: ftypes.CryptoIdentity{
				Method: ftypes.CryptoMethodSPKISHA256,
				Value:  "4f1c",
			},
			Name: "RSA public key",
			Key: &ftypes.CryptoKey{
				Size: size,
			},
			Relationships: []ftypes.CryptoRelationship{{
				Type:         ftypes.CryptoRelationshipUsedWith,
				RelatedAsset: algorithmDescriptor(algorithmOID, ""),
			}},
		},
		FilePath: filePath,
		Format:   format,
		Layer:    layer,
	})
}

func algorithm(filePath, oid, parameters string, classicalLevel *int) ftypes.CryptoAsset {
	return withID(ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind:     ftypes.CryptoKindAlgorithm,
			Identity: algorithmDescriptor(oid, parameters).Identity,
			Name:     "EC algorithm",
			Algorithm: &ftypes.CryptoAlgorithm{
				Primitive:              ftypes.CryptoPrimitiveUnknown,
				ClassicalSecurityLevel: classicalLevel,
			},
		},
		FilePath: filePath,
		Layer:    layer,
	})
}

func finding(ruleID, title, severity string, asset ftypes.CryptoAsset, evidence types.CryptoEvidence) types.CryptoFinding {
	return types.CryptoFinding{
		RuleID:   ruleID,
		Title:    title,
		Severity: severity,
		AssetID:  asset.AssetID,
		Evidence: evidence,
	}
}

func sha1Finding(asset ftypes.CryptoAsset, name, oid string) types.CryptoFinding {
	return finding("CRYPTO-0001", "SHA-1 certificate signature", "MEDIUM", asset,
		types.CryptoEvidence{
			SignatureAlgorithm:    name,
			SignatureAlgorithmOID: oid,
		})
}

func smallRSAKeyFinding(asset ftypes.CryptoAsset) types.CryptoFinding {
	return finding("CRYPTO-0002", "Small RSA key", "HIGH", asset,
		types.CryptoEvidence{
			KeySize: asset.Key.Size,
		})
}

func expiredFinding(asset ftypes.CryptoAsset) types.CryptoFinding {
	return finding("CRYPTO-0004", "Expired certificate", "MEDIUM", asset,
		types.CryptoEvidence{
			NotAfter: asset.Certificate.NotAfter,
		})
}

const (
	oidRSAEncryption = "1.2.840.113549.1.1.1"
	oidECPublicKey   = "1.2.840.10045.2.1"
	oidSHA256WithRSA = "1.2.840.113549.1.1.11"
)

func TestEvaluate(t *testing.T) {
	valid := now.AddDate(1, 0, 0)

	tests := []struct {
		name   string
		assets []ftypes.CryptoAsset
		want   []types.CryptoFinding
	}{
		{
			name:   "SHA-1 with RSA",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", "1.2.840.113549.1.1.5", valid)},
			want: []types.CryptoFinding{
				sha1Finding(certificate("cert.pem", "1.2.840.113549.1.1.5", valid), "RSA-PKCS1-1.5-SHA-1", "1.2.840.113549.1.1.5"),
			},
		},
		{
			name:   "SHA-1 with RSA under the OIW arc",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", "1.3.14.3.2.29", valid)},
			want: []types.CryptoFinding{
				sha1Finding(certificate("cert.pem", "1.3.14.3.2.29", valid), "RSA-PKCS1-1.5-SHA-1", "1.3.14.3.2.29"),
			},
		},
		{
			name:   "DSA with SHA-1",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", "1.2.840.10040.4.3", valid)},
			want: []types.CryptoFinding{
				sha1Finding(certificate("cert.pem", "1.2.840.10040.4.3", valid), "DSA-SHA-1", "1.2.840.10040.4.3"),
			},
		},
		{
			name:   "ECDSA with SHA-1",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", "1.2.840.10045.4.1", valid)},
			want: []types.CryptoFinding{
				sha1Finding(certificate("cert.pem", "1.2.840.10045.4.1", valid), "ECDSA-SHA-1", "1.2.840.10045.4.1"),
			},
		},
		{
			name:   "SHA-256 signature",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", oidSHA256WithRSA, valid)},
		},
		{
			name:   "RSA key below 2048 bits",
			assets: []ftypes.CryptoAsset{publicKey("key.pem", oidRSAEncryption, 2047, ftypes.CryptoKeyFormatPKIX)},
			want: []types.CryptoFinding{
				smallRSAKeyFinding(publicKey("key.pem", oidRSAEncryption, 2047, ftypes.CryptoKeyFormatPKIX)),
			},
		},
		{
			name:   "RSA key of 2048 bits",
			assets: []ftypes.CryptoAsset{publicKey("key.pem", oidRSAEncryption, 2048, ftypes.CryptoKeyFormatPKIX)},
		},
		{
			name:   "RSA key of unknown size",
			assets: []ftypes.CryptoAsset{publicKey("key.pem", oidRSAEncryption, 0, ftypes.CryptoKeyFormatPKIX)},
		},
		{
			name:   "small key of another algorithm",
			assets: []ftypes.CryptoAsset{publicKey("key.pem", "1.2.840.10040.4.1", 1024, ftypes.CryptoKeyFormatPKIX)},
		},
		{
			name:   "EC strength below 112 bits",
			assets: []ftypes.CryptoAsset{algorithm("key.pem", oidECPublicKey, "curve=P-192", new(96))},
			want: []types.CryptoFinding{
				finding("CRYPTO-0003", "Weak elliptic curve", "HIGH",
					algorithm("key.pem", oidECPublicKey, "curve=P-192", new(96)),
					types.CryptoEvidence{
						Curve:                  "P-192",
						ClassicalSecurityLevel: new(96),
					}),
			},
		},
		{
			name:   "EC strength of 112 bits",
			assets: []ftypes.CryptoAsset{algorithm("key.pem", oidECPublicKey, "curve=P-224", new(112))},
		},
		{
			name:   "EC strength unknown",
			assets: []ftypes.CryptoAsset{algorithm("key.pem", oidECPublicKey, "curve=secp256k1", nil)},
		},
		{
			name:   "weak algorithm other than EC",
			assets: []ftypes.CryptoAsset{algorithm("key.pem", oidRSAEncryption, "key-size=1024", new(80))},
		},
		{
			name:   "certificate expired before the evaluation time",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", oidSHA256WithRSA, now.Add(-time.Second))},
			want: []types.CryptoFinding{
				expiredFinding(certificate("cert.pem", oidSHA256WithRSA, now.Add(-time.Second))),
			},
		},
		{
			name:   "certificate expiring at the evaluation time",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", oidSHA256WithRSA, now)},
		},
		{
			name:   "certificate without an expiry",
			assets: []ftypes.CryptoAsset{certificate("cert.pem", oidSHA256WithRSA, time.Time{})},
		},
		{
			name: "certificate failing several checks",
			assets: []ftypes.CryptoAsset{
				certificate("cert.pem", "1.2.840.113549.1.1.5", now.Add(-time.Hour)),
				publicKey("cert.pem", oidRSAEncryption, 1024, ""),
			},
			want: []types.CryptoFinding{
				sha1Finding(certificate("cert.pem", "1.2.840.113549.1.1.5", now.Add(-time.Hour)), "RSA-PKCS1-1.5-SHA-1", "1.2.840.113549.1.1.5"),
				smallRSAKeyFinding(publicKey("cert.pem", oidRSAEncryption, 1024, "")),
				expiredFinding(certificate("cert.pem", "1.2.840.113549.1.1.5", now.Add(-time.Hour))),
			},
		},
		{
			name: "same key in a certificate, a PUBLIC KEY block and another file",
			assets: []ftypes.CryptoAsset{
				publicKey("b.pem", oidRSAEncryption, 1024, ftypes.CryptoKeyFormatPKIX),
				publicKey("a.pem", oidRSAEncryption, 1024, ftypes.CryptoKeyFormatPKIX),
				publicKey("a.pem", oidRSAEncryption, 1024, ""),
			},
			want: []types.CryptoFinding{
				smallRSAKeyFinding(publicKey("a.pem", oidRSAEncryption, 1024, "")),
				smallRSAKeyFinding(publicKey("a.pem", oidRSAEncryption, 1024, ftypes.CryptoKeyFormatPKIX)),
				smallRSAKeyFinding(publicKey("b.pem", oidRSAEncryption, 1024, ftypes.CryptoKeyFormatPKIX)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check.Evaluate(tt.assets, now)
			assert.Equal(t, tt.want, got)
		})
	}
}
