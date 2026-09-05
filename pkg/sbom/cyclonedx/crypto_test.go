package cyclonedx_test

import (
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

var (
	certificateDigest = strings.Repeat("a", 64)
	publicKeyDigest   = strings.Repeat("b", 64)
	encryptedDigest   = strings.Repeat("c", 64)

	signatureAlgorithmDescriptor = ftypes.CryptoDescriptor{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.2.840.113549.1.1.11",
		},
	}
	keyAlgorithmDescriptor = ftypes.CryptoDescriptor{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.113549.1.1.1",
			Parameters: "key-size=2048",
		},
	}
	publicKeyDescriptor = ftypes.CryptoDescriptor{
		Kind:    ftypes.CryptoKindKey,
		KeyType: ftypes.CryptoKeyTypePublic,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodSPKISHA256,
			Value:  publicKeyDigest,
		},
	}
)

func TestMarshaler_MarshalCryptoAssets(t *testing.T) {
	tests := []struct {
		name   string
		assets []ftypes.CryptoAsset
		want   []cdx.Component
	}{
		{
			name: "certificate",
			assets: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind: ftypes.CryptoKindCertificate,
						Identity: ftypes.CryptoIdentity{
							Method: ftypes.CryptoMethodSHA256,
							Value:  certificateDigest,
						},
						Name: "example.com",
						Certificate: &ftypes.CryptoCertificate{
							Subject:               "CN=example.com,O=Example",
							Issuer:                "CN=Example CA,O=Example",
							SerialNumber:          "2a",
							NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
							NotAfter:              time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Format:                ftypes.CryptoCertificateFormatX509,
							Encoding:              ftypes.CryptoEncodingPEM,
							KeyUsage:              []string{"digital signature", "certificate sign"},
							ExtendedKeyUsage:      []string{"server auth"},
							DNSNames:              []string{"example.com", "www.example.com"},
							EmailAddresses:        []string{"security@example.com"},
							IPAddresses:           []string{"192.0.2.1"},
							URIs:                  []string{"spiffe://example.com/service"},
							BasicConstraintsValid: true,
							IsCA:                  true,
							MaxPathLenZero:        true,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: signatureAlgorithmDescriptor,
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: publicKeyDescriptor,
							},
						},
					},
					FilePath: "etc/ssl/certs/server.crt",
				},
			},
			want: []cdx.Component{
				{
					BOMRef: "crypto:certificate:sha256:" + certificateDigest,
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   "example.com",
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeCertificate,
						CertificateProperties: &cdx.CertificateProperties{
							SerialNumber:      "2a",
							SubjectName:       "CN=example.com,O=Example",
							IssuerName:        "CN=Example CA,O=Example",
							NotValidBefore:    "2024-01-01T00:00:00+00:00",
							NotValidAfter:     "2025-01-01T00:00:00+00:00",
							CertificateFormat: "X.509",
							Fingerprint: &cdx.Hash{
								Algorithm: cdx.HashAlgoSHA256,
								Value:     certificateDigest,
							},
							CertificateExtensions: &[]cdx.CertificateExtension{
								{
									Common: &cdx.CommonCertificateExtension{
										Name:  cdx.CertExtBasicConstraints,
										Value: "CA:TRUE, pathlen:0",
									},
								},
								{
									Common: &cdx.CommonCertificateExtension{
										Name:  cdx.CertExtKeyUsage,
										Value: "digital signature, certificate sign",
									},
								},
								{
									Common: &cdx.CommonCertificateExtension{
										Name:  cdx.CertExtExtendedKeyUsage,
										Value: "server auth",
									},
								},
								{
									Common: &cdx.CommonCertificateExtension{
										Name:  cdx.CertExtSubjectAlternativeName,
										Value: "DNS:example.com, DNS:www.example.com, email:security@example.com, IP:192.0.2.1, URI:spiffe://example.com/service",
									},
								},
							},
							RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{
								{
									Type: "algorithm",
									Ref:  "crypto:algorithm:oid:1.2.840.113549.1.1.11",
								},
								{
									Type: "publicKey",
									Ref:  "crypto:key:public:spki-sha256:" + publicKeyDigest,
								},
							},
						},
					},
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: "etc/ssl/certs/server.crt"},
						},
					},
				},
			},
		},
		{
			name: "public key and its algorithm",
			assets: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindKey,
						KeyType:  ftypes.CryptoKeyTypePublic,
						Identity: publicKeyDescriptor.Identity,
						Name:     "RSA-2048 public key",
						Key: &ftypes.CryptoKey{
							Size:     2048,
							Format:   ftypes.CryptoKeyFormatPKIX,
							Encoding: ftypes.CryptoEncodingPEM,
						},
						Relationships: []ftypes.CryptoRelationship{{
							Type:         ftypes.CryptoRelationshipUsedWith,
							RelatedAsset: keyAlgorithmDescriptor,
						}},
					},
					FilePath: "opt/app/public.pem",
				},
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindAlgorithm,
						Identity: keyAlgorithmDescriptor.Identity,
						Name:     "RSA-2048",
						Algorithm: &ftypes.CryptoAlgorithm{
							Primitive: ftypes.CryptoPrimitiveUnknown,
						},
					},
					FilePath: "opt/app/public.pem",
				},
			},
			want: []cdx.Component{
				{
					BOMRef: "crypto:algorithm:oid:1.2.840.113549.1.1.1:key-size%3D2048",
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   "RSA-2048",
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeAlgorithm,
						AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
							Primitive:              cdx.CryptoPrimitiveUnknown,
							ParameterSetIdentifier: "2048",
						},
						OID: "1.2.840.113549.1.1.1",
					},
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: "opt/app/public.pem"},
						},
					},
				},
				{
					BOMRef: "crypto:key:public:spki-sha256:" + publicKeyDigest,
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   "RSA-2048 public key",
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
						RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
							Type:   cdx.RelatedCryptoMaterialTypePublicKey,
							Size:   new(2048),
							Format: "PKIX",
							Fingerprint: &cdx.Hash{
								Algorithm: cdx.HashAlgoSHA256,
								Value:     publicKeyDigest,
							},
							RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{
								Type: "algorithm",
								Ref:  "crypto:algorithm:oid:1.2.840.113549.1.1.1:key-size%3D2048",
							}},
						},
					},
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: "opt/app/public.pem"},
						},
					},
				},
			},
		},
		{
			name: "encrypted private key",
			assets: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:    ftypes.CryptoKindKey,
						KeyType: ftypes.CryptoKeyTypePrivate,
						Identity: ftypes.CryptoIdentity{
							Method: ftypes.CryptoMethodEncryptedPKCS8SHA256,
							Value:  encryptedDigest,
						},
						Name: "Encrypted PKCS#8 private key",
						Key: &ftypes.CryptoKey{
							Format:    ftypes.CryptoKeyFormatPKCS8,
							Encoding:  ftypes.CryptoEncodingPEM,
							Encrypted: true,
						},
					},
					FilePath: "opt/app/private.pem",
				},
			},
			want: []cdx.Component{
				{
					BOMRef: "crypto:key:private:encrypted-pkcs8-sha256:" + encryptedDigest,
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   "Encrypted PKCS#8 private key",
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
						RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
							Type:   cdx.RelatedCryptoMaterialTypePrivateKey,
							Format: "PKCS#8",
							Fingerprint: &cdx.Hash{
								Algorithm: cdx.HashAlgoSHA256,
								Value:     encryptedDigest,
							},
						},
					},
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: "opt/app/private.pem"},
						},
					},
				},
			},
		},
		{
			name: "elliptic curve algorithm",
			assets: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind: ftypes.CryptoKindAlgorithm,
						Identity: ftypes.CryptoIdentity{
							Method:     ftypes.CryptoMethodOID,
							Value:      "1.2.840.10045.2.1",
							Parameters: "curve=P-256",
						},
						Name: "EC-P-256",
						Algorithm: &ftypes.CryptoAlgorithm{
							Primitive: ftypes.CryptoPrimitiveUnknown,
						},
					},
					FilePath: "opt/app/ec.pem",
				},
			},
			want: []cdx.Component{
				{
					BOMRef: "crypto:algorithm:oid:1.2.840.10045.2.1:curve%3DP-256",
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   "EC-P-256",
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeAlgorithm,
						AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
							Primitive:     cdx.CryptoPrimitiveUnknown,
							EllipticCurve: "nist/P-256",
						},
						OID: "1.2.840.10045.2.1",
					},
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: "opt/app/ec.pem"},
						},
					},
				},
			},
		},
		{
			name: "one asset found in several files",
			assets: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind: ftypes.CryptoKindAlgorithm,
						Identity: ftypes.CryptoIdentity{
							Method: ftypes.CryptoMethodOID,
							Value:  "1.2.840.113549.1.1.11",
						},
						Name: "RSA-PKCS1-1.5-SHA-256",
						Algorithm: &ftypes.CryptoAlgorithm{
							Family:    "RSASSA-PKCS1",
							Primitive: ftypes.CryptoPrimitiveSignature,
						},
					},
					FilePath: "etc/ssl/certs/ca-certificates.crt",
				},
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind: ftypes.CryptoKindAlgorithm,
						Identity: ftypes.CryptoIdentity{
							Method: ftypes.CryptoMethodOID,
							Value:  "1.2.840.113549.1.1.11",
						},
						Name: "RSA-PKCS1-1.5-SHA-256",
						Algorithm: &ftypes.CryptoAlgorithm{
							Family:    "RSASSA-PKCS1",
							Primitive: ftypes.CryptoPrimitiveSignature,
						},
					},
					FilePath: "opt/app/server.crt",
				},
			},
			want: []cdx.Component{
				{
					BOMRef: "crypto:algorithm:oid:1.2.840.113549.1.1.11",
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   "RSA-PKCS1-1.5-SHA-256",
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeAlgorithm,
						AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
							Primitive:       cdx.CryptoPrimitiveSignature,
							AlgorithmFamily: "RSASSA-PKCS1",
						},
						OID: "1.2.840.113549.1.1.11",
					},
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: "etc/ssl/certs/ca-certificates.crt"},
							{Location: "opt/app/server.crt"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			marshaler := cyclonedx.NewMarshaler("dev")
			got, err := marshaler.MarshalReport(ctx, cryptoReport(tt.assets))
			require.NoError(t, err)

			assets := lo.Filter(lo.FromPtr(got.Components), func(component cdx.Component, _ int) bool {
				return component.Type == cdx.ComponentTypeCryptographicAsset
			})
			assert.Equal(t, tt.want, assets)
		})
	}
}

// Every reference between cryptographic assets points at a component of the same document.
func TestMarshaler_MarshalCryptoAssetReferences(t *testing.T) {
	certificate := ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind: ftypes.CryptoKindCertificate,
			Identity: ftypes.CryptoIdentity{
				Method: ftypes.CryptoMethodSHA256,
				Value:  certificateDigest,
			},
			Name: "example.com",
			Certificate: &ftypes.CryptoCertificate{
				Subject: "CN=example.com",
				Issuer:  "CN=example.com",
				Format:  ftypes.CryptoCertificateFormatX509,
			},
			Relationships: []ftypes.CryptoRelationship{
				{
					Type:         ftypes.CryptoRelationshipSignedWith,
					RelatedAsset: signatureAlgorithmDescriptor,
				},
				{
					Type:         ftypes.CryptoRelationshipContains,
					RelatedAsset: publicKeyDescriptor,
				},
			},
		},
		FilePath: "etc/ssl/certs/server.crt",
	}
	signatureAlgorithm := ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind:     ftypes.CryptoKindAlgorithm,
			Identity: signatureAlgorithmDescriptor.Identity,
			Name:     "RSA-PKCS1-1.5-SHA-256",
			Algorithm: &ftypes.CryptoAlgorithm{
				Family:    "RSASSA-PKCS1",
				Primitive: ftypes.CryptoPrimitiveSignature,
			},
		},
		FilePath: "etc/ssl/certs/server.crt",
	}
	key := ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind:     ftypes.CryptoKindKey,
			KeyType:  ftypes.CryptoKeyTypePublic,
			Identity: publicKeyDescriptor.Identity,
			Name:     "RSA-2048 public key",
			Key:      &ftypes.CryptoKey{Size: 2048},
			Relationships: []ftypes.CryptoRelationship{{
				Type:         ftypes.CryptoRelationshipUsedWith,
				RelatedAsset: keyAlgorithmDescriptor,
			}},
		},
		FilePath: "etc/ssl/certs/server.crt",
	}
	keyAlgorithm := ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind:      ftypes.CryptoKindAlgorithm,
			Identity:  keyAlgorithmDescriptor.Identity,
			Name:      "RSA-2048",
			Algorithm: &ftypes.CryptoAlgorithm{Primitive: ftypes.CryptoPrimitiveUnknown},
		},
		FilePath: "etc/ssl/certs/server.crt",
	}

	ctx := clock.With(t.Context(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
	uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

	marshaler := cyclonedx.NewMarshaler("dev")
	got, err := marshaler.MarshalReport(ctx, cryptoReport([]ftypes.CryptoAsset{
		certificate,
		signatureAlgorithm,
		key,
		keyAlgorithm,
	}))
	require.NoError(t, err)

	refs := lo.SliceToMap(lo.FromPtr(got.Components), func(component cdx.Component) (string, struct{}) {
		return component.BOMRef, struct{}{}
	})

	var related []cdx.RelatedCryptographicAsset
	for _, component := range lo.FromPtr(got.Components) {
		if component.CryptoProperties == nil {
			continue
		}
		if properties := component.CryptoProperties.CertificateProperties; properties != nil {
			related = append(related, lo.FromPtr(properties.RelatedCryptographicAssets)...)
		}
		if properties := component.CryptoProperties.RelatedCryptoMaterialProperties; properties != nil {
			related = append(related, lo.FromPtr(properties.RelatedCryptographicAssets)...)
		}
	}

	require.Len(t, related, 3)
	for _, reference := range related {
		assert.Contains(t, refs, reference.Ref)
	}
}

// A cryptographic asset depends on nothing, which CycloneDX states by declaring the
// component as an empty element of the dependency graph.
func TestMarshaler_MarshalCryptoAssetDependencies(t *testing.T) {
	ctx := clock.With(t.Context(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
	uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

	marshaler := cyclonedx.NewMarshaler("dev")
	got, err := marshaler.MarshalReport(ctx, cryptoReport([]ftypes.CryptoAsset{
		cryptotest.CertificateAsset(),
		cryptotest.AlgorithmAsset(),
	}))
	require.NoError(t, err)

	dependencies := lo.SliceToMap(lo.FromPtr(got.Dependencies), func(dependency cdx.Dependency) (string, *[]string) {
		return dependency.Ref, dependency.Dependencies
	})

	assets := lo.Filter(lo.FromPtr(got.Components), func(component cdx.Component, _ int) bool {
		return component.Type == cdx.ComponentTypeCryptographicAsset
	})
	require.Len(t, assets, 2)

	for _, asset := range assets {
		deps, ok := dependencies[asset.BOMRef]
		require.True(t, ok, asset.BOMRef)
		require.NotNil(t, deps, asset.BOMRef)
		assert.Empty(t, *deps, asset.BOMRef)
	}
}

func cryptoReport(assets []ftypes.CryptoAsset) types.Report {
	return types.Report{
		SchemaVersion: 2,
		ArtifactName:  "debian:12",
		ArtifactType:  ftypes.TypeContainerImage,
		Results: types.Results{
			{
				Target:       "debian:12",
				Class:        types.ClassCrypto,
				CryptoAssets: assets,
			},
		},
	}
}
