package crypto_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/crypto"
)

func TestAssetDescriptor(t *testing.T) {
	t.Parallel()

	asset := cryptotest.CertificateAsset()
	want := crypto.Descriptor{
		Kind:     asset.Kind,
		KeyType:  asset.KeyType,
		Identity: asset.Identity,
	}
	// The first call caches the descriptor's kind, key type, and identity.
	assert.Equal(t, want, asset.Descriptor())

	asset.Kind = crypto.KindKey
	asset.KeyType = crypto.KeyTypePrivate
	asset.Identity = crypto.Identity{
		Method: crypto.MethodSPKISHA256,
		Value:  strings.Repeat("b", 64),
	}
	// Later mutations to all descriptor source fields do not change the cached value.
	assert.Equal(t, want, asset.Descriptor())
}

func TestAssetDescriptorJSONRoundTrip(t *testing.T) {
	t.Parallel()

	source := cryptotest.CertificateAsset()
	cached := source.Descriptor()
	source.Identity.Value = strings.Repeat("b", 64)

	// Marshal writes only the source fields and excludes the internal descriptor cache.
	data, err := json.Marshal(source)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "descriptor")
	assert.NotContains(t, string(data), cached.Identity.Value)

	// Unmarshal restores the source fields without restoring the descriptor cache.
	var got crypto.Asset
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, source.Identity, got.Identity)

	// The first Descriptor call on the decoded asset populates a new cache.
	want := crypto.Descriptor{
		Kind:     got.Kind,
		KeyType:  got.KeyType,
		Identity: got.Identity,
	}
	assert.Equal(t, want, got.Descriptor())

	// Mutating the decoded identity proves subsequent calls use that new cache.
	got.Identity.Value = strings.Repeat("c", 64)
	assert.Equal(t, want, got.Descriptor())
}

func TestAssetValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		asset   crypto.Asset
		wantErr string
	}{
		{
			name:    "certificate",
			asset:   cryptotest.CertificateAsset(),
			wantErr: "",
		},
		{
			name:    "public key",
			asset:   cryptotest.PublicKeyAsset(),
			wantErr: "",
		},
		{
			name: "derived public key without format or encoding",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
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
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Identity.Parameters = "key-size=2048"
			})),
			wantErr: "",
		},
		{
			name: "algorithm with curve",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Identity.Parameters = "curve=P-256"
			})),
			wantErr: "",
		},
		{
			name: "missing detail",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Certificate = nil
			})),
			wantErr: "asset must contain exactly one detail, got 0",
		},
		{
			name: "multiple details",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key = &crypto.Key{}
			})),
			wantErr: "asset must contain exactly one detail, got 2",
		},
		{
			name: "certificate detail on key",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Certificate = &crypto.Certificate{Format: crypto.CertificateFormatX509}
				a.Key = nil
			})),
			wantErr: `asset kind "key" requires key details`,
		},
		{
			name: "key detail on algorithm",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key = &crypto.Key{}
				a.Algorithm = nil
			})),
			wantErr: `asset kind "algorithm" requires algorithm details`,
		},
		{
			name: "algorithm detail on certificate",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Algorithm = &crypto.Algorithm{Primitive: crypto.PrimitiveUnknown}
				a.Certificate = nil
			})),
			wantErr: `asset kind "certificate" requires certificate details`,
		},
		{
			name: "unencrypted encrypted container",
			asset: cryptotest.EncryptedPrivateKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key.Encrypted = false
			})),
			wantErr: `key encrypted flag does not match identification method "encrypted-pkcs8-sha256"`,
		},
		{
			name: "encrypted plain key",
			asset: cryptotest.PrivateKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key.Encrypted = true
			})),
			wantErr: `key encrypted flag does not match identification method "spki-sha256"`,
		},
		{
			name: "unknown certificate format",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Certificate.Format = "PEM"
			})),
			wantErr: `unknown certificate format "PEM"`,
		},
		{
			name: "unknown key format",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key.Format = "OpenSSH"
			})),
			wantErr: `unknown key format "OpenSSH"`,
		},
		{
			name: "unknown key encoding",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key.Encoding = "SSH"
			})),
			wantErr: `unknown key encoding "SSH"`,
		},
		{
			name: "unknown primitive",
			asset: cryptotest.AlgorithmAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Algorithm.Primitive = "hash"
			})),
			wantErr: `unknown algorithm primitive "hash"`,
		},
		{
			name: "negative key size",
			asset: cryptotest.PublicKeyAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
				a.Key.Size = -1
			})),
			wantErr: "key size must not be negative",
		},
		{
			name: "negative normalized path length",
			asset: cryptotest.CertificateAsset(cryptotest.WithMutate(func(a *crypto.Asset) {
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

func TestAssetValidateRelationships(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		relationship  crypto.Relationship
		selfReference bool
		wantErr       string
	}{
		{
			name: "contains",
			relationship: crypto.Relationship{
				Type:         crypto.RelationshipContains,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "signed with",
			relationship: crypto.Relationship{
				Type:         crypto.RelationshipSignedWith,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "used with",
			relationship: crypto.Relationship{
				Type:         crypto.RelationshipUsedWith,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "corresponds to",
			relationship: crypto.Relationship{
				Type:         crypto.RelationshipCorrespondsTo,
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
		},
		{
			name: "unknown type",
			relationship: crypto.Relationship{
				Type:         "issued_by",
				RelatedAsset: cryptotest.PublicKeyDescriptor(),
			},
			wantErr: `unknown relationship type "issued_by"`,
		},
		{
			name: "invalid related descriptor",
			relationship: crypto.Relationship{
				Type: crypto.RelationshipContains,
				RelatedAsset: crypto.Descriptor{
					Kind: crypto.KindAlgorithm,
					Identity: crypto.Identity{
						Method: crypto.MethodOID,
						Value:  "1.02.3",
					},
				},
			},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name: "self-reference",
			relationship: crypto.Relationship{
				Type: crypto.RelationshipContains,
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
			a.Relationships = []crypto.Relationship{tt.relationship}

			err := a.Validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAssetClone(t *testing.T) {
	t.Parallel()

	t.Run("certificate", func(t *testing.T) {
		t.Parallel()

		source := cryptotest.CertificateAsset()
		source.Certificate.KeyUsage = []string{"digital signature"}
		source.Certificate.ExtendedKeyUsage = []string{"server auth"}
		source.Certificate.DNSNames = []string{"example.com"}
		source.Certificate.EmailAddresses = []string{"security@example.com"}
		source.Certificate.IPAddresses = []string{"192.0.2.1"}
		source.Certificate.URIs = []string{"spiffe://example.com/service"}
		source.Relationships = []crypto.Relationship{{
			Type:         crypto.RelationshipContains,
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
		clone.Relationships[0].Type = crypto.RelationshipSignedWith

		assert.Equal(t, "CN=example.test", source.Certificate.Subject)
		assert.Equal(t, []string{"digital signature"}, source.Certificate.KeyUsage)
		assert.Equal(t, []string{"server auth"}, source.Certificate.ExtendedKeyUsage)
		assert.Equal(t, []string{"example.com"}, source.Certificate.DNSNames)
		assert.Equal(t, []string{"security@example.com"}, source.Certificate.EmailAddresses)
		assert.Equal(t, []string{"192.0.2.1"}, source.Certificate.IPAddresses)
		assert.Equal(t, []string{"spiffe://example.com/service"}, source.Certificate.URIs)
		assert.Equal(t, crypto.RelationshipContains, source.Relationships[0].Type)
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
