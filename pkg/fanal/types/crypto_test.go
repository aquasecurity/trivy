package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestCryptoAlgorithmJSON(t *testing.T) {
	t.Parallel()

	got, err := json.Marshal(types.CryptoAlgorithm{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"Primitive":""}`, string(got))
}

func TestCryptoAssetDescriptor(t *testing.T) {
	t.Parallel()

	asset := cryptotest.PublicKeyAsset()
	// Descriptor projects the fields that make up the asset's identity.
	want := types.CryptoDescriptor{
		Kind:    types.CryptoKindKey,
		KeyType: types.CryptoKeyTypePublic,
		Identity: types.CryptoIdentity{
			Method: types.CryptoMethodSPKISHA256,
			Value:  strings.Repeat("b", 64),
		},
	}
	assert.Equal(t, want, asset.Descriptor())

	asset.Kind = types.CryptoKindAlgorithm
	asset.KeyType = ""
	asset.Identity = types.CryptoIdentity{
		Method:     types.CryptoMethodOID,
		Value:      "1.2.840.10045.2.1",
		Parameters: "curve=P-256",
	}
	// Changes to those fields are reflected in the next projection.
	want = types.CryptoDescriptor{
		Kind: types.CryptoKindAlgorithm,
		Identity: types.CryptoIdentity{
			Method:     types.CryptoMethodOID,
			Value:      "1.2.840.10045.2.1",
			Parameters: "curve=P-256",
		},
	}
	assert.Equal(t, want, asset.Descriptor())
}

func TestCryptoAssetValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		asset   types.CryptoAsset
		wantErr string
	}{
		{
			name:    "certificate",
			asset:   cryptotest.CertificateAsset(),
			wantErr: "",
		},
		{
			name: "DER certificate",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate.Encoding = types.CryptoEncodingDER
			})),
			wantErr: "",
		},
		{
			name: "explicit zero certificate path length",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate.MaxPathLenZero = true
			})),
			wantErr: "",
		},
		{
			name: "non-zero certificate path length with zero flag",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate.MaxPathLen = 1
				a.Certificate.MaxPathLenZero = true
			})),
			wantErr: "certificate path length zero flag requires zero path length",
		},
		{
			name:    "public key",
			asset:   cryptotest.PublicKeyAsset(),
			wantErr: "",
		},
		{
			name: "derived public key without format or encoding",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key.Format = ""
				a.Key.Encoding = ""
			})),
			wantErr: "",
		},
		{
			name:    "private key",
			asset:   cryptotest.PrivateKeyAsset(),
			wantErr: "",
		},
		{
			name:    "encrypted private key",
			asset:   cryptotest.EncryptedPrivateKeyAsset(),
			wantErr: "",
		},
		{
			name:    "algorithm without parameters",
			asset:   cryptotest.AlgorithmAsset(),
			wantErr: "",
		},
		{
			name: "algorithm with key size",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Identity.Parameters = "key-size=2048"
			})),
			wantErr: "",
		},
		{
			name: "algorithm with curve",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Identity.Parameters = "curve=P-256"
			})),
			wantErr: "",
		},
		{
			name: "missing detail",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate = nil
			})),
			wantErr: "asset must contain exactly one detail, got 0",
		},
		{
			name: "multiple details",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key = &types.CryptoKey{}
			})),
			wantErr: "asset must contain exactly one detail, got 2",
		},
		{
			name: "certificate detail on key",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate = &types.CryptoCertificate{Format: types.CryptoCertificateFormatX509}
				a.Key = nil
			})),
			wantErr: `asset kind "key" requires key details`,
		},
		{
			name: "key detail on algorithm",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key = &types.CryptoKey{}
				a.Algorithm = nil
			})),
			wantErr: `asset kind "algorithm" requires algorithm details`,
		},
		{
			name: "algorithm detail on certificate",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Algorithm = &types.CryptoAlgorithm{Primitive: types.CryptoPrimitiveUnknown}
				a.Certificate = nil
			})),
			wantErr: `asset kind "certificate" requires certificate details`,
		},
		{
			name: "unencrypted encrypted container",
			asset: cryptotest.EncryptedPrivateKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key.Encrypted = false
			})),
			wantErr: `key encrypted flag does not match identification method "encrypted-pkcs8-sha256"`,
		},
		{
			name: "encrypted plain key",
			asset: cryptotest.PrivateKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key.Encrypted = true
			})),
			wantErr: `key encrypted flag does not match identification method "spki-sha256"`,
		},
		{
			name: "unknown certificate format",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate.Format = "PEM"
			})),
			wantErr: `unknown certificate format "PEM"`,
		},
		{
			name: "unknown certificate encoding",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate.Encoding = "SSH"
			})),
			wantErr: `unknown certificate encoding "SSH"`,
		},
		{
			name: "unknown key format",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key.Format = "OpenSSH"
			})),
			wantErr: `unknown key format "OpenSSH"`,
		},
		{
			name: "unknown key encoding",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key.Encoding = "SSH"
			})),
			wantErr: `unknown key encoding "SSH"`,
		},
		{
			name: "unknown primitive",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Algorithm.Primitive = "hash"
			})),
			wantErr: `unknown algorithm primitive "hash"`,
		},
		{
			name: "negative key size",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Key.Size = -1
			})),
			wantErr: "key size must not be negative",
		},
		{
			name: "negative normalized path length",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *types.CryptoAsset) {
				a.Certificate.MaxPathLen = -1
			})),
			wantErr: "certificate path length must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.asset.Validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCryptoAssetValidateRelationships(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		relationship  types.CryptoRelationship
		selfReference bool
		wantErr       string
	}{
		{
			name: "contains",
			relationship: types.CryptoRelationship{
				Type:         types.CryptoRelationshipContains,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "signed with",
			relationship: types.CryptoRelationship{
				Type:         types.CryptoRelationshipSignedWith,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "used with",
			relationship: types.CryptoRelationship{
				Type:         types.CryptoRelationshipUsedWith,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "corresponds to",
			relationship: types.CryptoRelationship{
				Type:         types.CryptoRelationshipCorrespondsTo,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "unknown type",
			relationship: types.CryptoRelationship{
				Type:         "issued_by",
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
			wantErr: `unknown relationship type "issued_by"`,
		},
		{
			name: "invalid related descriptor",
			relationship: types.CryptoRelationship{
				Type: types.CryptoRelationshipContains,
				RelatedAsset: types.CryptoDescriptor{
					Kind: types.CryptoKindAlgorithm,
					Identity: types.CryptoIdentity{
						Method: types.CryptoMethodOID,
						Value:  "1.02.3",
					},
				},
			},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name: "self-reference",
			relationship: types.CryptoRelationship{
				Type: types.CryptoRelationshipContains,
			},
			selfReference: true,
			wantErr:       "relationship 0 refers to the source asset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := cryptotest.CertificateAsset()
			if tt.selfReference {
				tt.relationship.RelatedAsset = a.Descriptor()
			}
			a.Relationships = []types.CryptoRelationship{tt.relationship}

			err := a.Validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCryptoAssetClone(t *testing.T) {
	t.Parallel()

	t.Run("certificate", func(t *testing.T) {
		t.Parallel()

		source := cryptotest.CertificateAsset()
		source.Layer = types.Layer{
			Size:      1024,
			Digest:    "sha256:layer",
			DiffID:    "sha256:diff-id",
			CreatedBy: "COPY certificate.pem /etc/ssl/",
		}
		source.Certificate.KeyUsage = []string{"digital signature"}
		source.Certificate.ExtendedKeyUsage = []string{"server auth"}
		source.Certificate.DNSNames = []string{"example.com"}
		source.Certificate.EmailAddresses = []string{"security@example.com"}
		source.Certificate.IPAddresses = []string{"192.0.2.1"}
		source.Certificate.URIs = []string{"spiffe://example.com/service"}
		source.Relationships = []types.CryptoRelationship{{
			Type:         types.CryptoRelationshipContains,
			RelatedAsset: cryptotest.PublicKeyDescriptor(),
		}}

		clone := source.Clone()
		require.NotSame(t, source.Certificate, clone.Certificate)
		assert.Equal(t, source, clone)

		// Mutating every nested mutable field proves the clone shares no mutable storage with the source.
		clone.Certificate.Subject = "changed"
		clone.Certificate.KeyUsage[0] = "changed"
		clone.Certificate.ExtendedKeyUsage[0] = "changed"
		clone.Certificate.DNSNames[0] = "changed"
		clone.Certificate.EmailAddresses[0] = "changed"
		clone.Certificate.IPAddresses[0] = "changed"
		clone.Certificate.URIs[0] = "changed"
		clone.Relationships[0].Type = types.CryptoRelationshipSignedWith

		assert.Equal(t, "CN=example.test", source.Certificate.Subject)
		assert.Equal(t, []string{"digital signature"}, source.Certificate.KeyUsage)
		assert.Equal(t, []string{"server auth"}, source.Certificate.ExtendedKeyUsage)
		assert.Equal(t, []string{"example.com"}, source.Certificate.DNSNames)
		assert.Equal(t, []string{"security@example.com"}, source.Certificate.EmailAddresses)
		assert.Equal(t, []string{"192.0.2.1"}, source.Certificate.IPAddresses)
		assert.Equal(t, []string{"spiffe://example.com/service"}, source.Certificate.URIs)
		assert.Equal(t, types.CryptoRelationshipContains, source.Relationships[0].Type)
	})

	t.Run("key", func(t *testing.T) {
		t.Parallel()

		source := cryptotest.PublicKeyAsset()
		clone := source.Clone()
		require.NotSame(t, source.Key, clone.Key)
		assert.Equal(t, source, clone)

		clone.Key.Size = 4096
		assert.Equal(t, 2048, source.Key.Size)
	})

	t.Run("algorithm", func(t *testing.T) {
		t.Parallel()

		source := cryptotest.AlgorithmAsset()
		clone := source.Clone()
		require.NotSame(t, source.Algorithm, clone.Algorithm)
		assert.Equal(t, source, clone)

		clone.Algorithm.Family = "changed"
		assert.Equal(t, "RSA", source.Algorithm.Family)
	})
}
