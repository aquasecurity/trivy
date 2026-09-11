package crypto_test

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type keyFixtures struct {
	rsaPublic     *rsa.PublicKey
	ecdsaPublic   *ecdsa.PublicKey
	ed25519Public ed25519.PublicKey
	dsaPublic     *dsa.PublicKey
	mldsaPublic   *mldsa.PublicKey
}

func TestDescribeKey(t *testing.T) {
	fixtures := newKeyFixtures(t)

	// The algorithm of an RSA key cannot be told apart from a signature algorithm by its
	// OID alone, so it carries an unknown primitive and no family.
	rsaAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.113549.1.1.1",
			Parameters: "key-size=2048",
		},
		Name: "RSA-2048",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	ecAlgorithm := ftypes.CryptoAssetInfo{
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
	}
	ed25519Algorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.3.101.112",
		},
		Name: "Ed25519",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "EdDSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	dsaAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.10040.4.1",
			Parameters: "key-size=2048",
		},
		Name: "DSA-2048",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "DSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	mldsaAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "2.16.840.1.101.3.4.3.17",
		},
		Name: "ML-DSA-44",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "ML-DSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}

	tests := []struct {
		name          string
		pub           any
		keyType       ftypes.CryptoKeyType
		format        ftypes.CryptoKeyFormat
		encoding      ftypes.CryptoEncoding
		wantKey       ftypes.CryptoAssetInfo
		wantAlgorithm ftypes.CryptoAssetInfo
	}{
		{
			name:     "RSA public key",
			pub:      fixtures.rsaPublic,
			keyType:  ftypes.CryptoKeyTypePublic,
			format:   ftypes.CryptoKeyFormatPKIX,
			encoding: ftypes.CryptoEncodingPEM,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePublic,
				Identity: spkiIdentity(t, fixtures.rsaPublic),
				Name:     "RSA-2048 public key",
				Key: &ftypes.CryptoKey{
					Size:     2048,
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: rsaAlgorithm.Descriptor(),
				}},
			},
			wantAlgorithm: rsaAlgorithm,
		},
		{
			name:     "ECDSA public key",
			pub:      fixtures.ecdsaPublic,
			keyType:  ftypes.CryptoKeyTypePublic,
			format:   ftypes.CryptoKeyFormatPKIX,
			encoding: ftypes.CryptoEncodingDER,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePublic,
				Identity: spkiIdentity(t, fixtures.ecdsaPublic),
				Name:     "EC-P-256 public key",
				Key: &ftypes.CryptoKey{
					Size:     256,
					Curve:    "P-256",
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingDER,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: ecAlgorithm.Descriptor(),
				}},
			},
			wantAlgorithm: ecAlgorithm,
		},
		{
			name:     "Ed25519 public key",
			pub:      fixtures.ed25519Public,
			keyType:  ftypes.CryptoKeyTypePublic,
			format:   ftypes.CryptoKeyFormatPKIX,
			encoding: ftypes.CryptoEncodingPEM,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePublic,
				Identity: spkiIdentity(t, fixtures.ed25519Public),
				Name:     "Ed25519 public key",
				Key: &ftypes.CryptoKey{
					Size:     256,
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: ed25519Algorithm.Descriptor(),
				}},
			},
			wantAlgorithm: ed25519Algorithm,
		},
		{
			// crypto/x509 parses a DSA key but cannot encode it, so the canonical form
			// comes from this package.
			name:     "DSA public key",
			pub:      fixtures.dsaPublic,
			keyType:  ftypes.CryptoKeyTypePublic,
			format:   ftypes.CryptoKeyFormatPKIX,
			encoding: ftypes.CryptoEncodingDER,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePublic,
				Identity: spkiIdentity(t, fixtures.dsaPublic),
				Name:     "DSA-2048 public key",
				Key: &ftypes.CryptoKey{
					Size:     2048,
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingDER,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: dsaAlgorithm.Descriptor(),
				}},
			},
			wantAlgorithm: dsaAlgorithm,
		},
		{
			// The parameter set of an ML-DSA key is part of its OID, so the algorithm
			// carries no parameter and the key size states the length of the encoding.
			name:     "ML-DSA public key",
			pub:      fixtures.mldsaPublic,
			keyType:  ftypes.CryptoKeyTypePublic,
			format:   ftypes.CryptoKeyFormatPKIX,
			encoding: ftypes.CryptoEncodingPEM,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePublic,
				Identity: spkiIdentity(t, fixtures.mldsaPublic),
				Name:     "ML-DSA-44 public key",
				Key: &ftypes.CryptoKey{
					// The 1312 bytes an ML-DSA-44 public key always takes.
					Size:     10496,
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: mldsaAlgorithm.Descriptor(),
				}},
			},
			wantAlgorithm: mldsaAlgorithm,
		},
		{
			// A private key is described through its public projection, so only the key
			// type and the container tell the two apart.
			name:     "private key",
			pub:      fixtures.rsaPublic,
			keyType:  ftypes.CryptoKeyTypePrivate,
			format:   ftypes.CryptoKeyFormatPKCS8,
			encoding: ftypes.CryptoEncodingPEM,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePrivate,
				Identity: spkiIdentity(t, fixtures.rsaPublic),
				Name:     "RSA-2048 private key",
				Key: &ftypes.CryptoKey{
					Size:     2048,
					Format:   ftypes.CryptoKeyFormatPKCS8,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: rsaAlgorithm.Descriptor(),
				}},
			},
			wantAlgorithm: rsaAlgorithm,
		},
		{
			// A key with no container of its own states neither format nor encoding, which
			// is how the key of a certificate is described.
			name:    "key without a container",
			pub:     fixtures.rsaPublic,
			keyType: ftypes.CryptoKeyTypePublic,
			wantKey: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePublic,
				Identity: spkiIdentity(t, fixtures.rsaPublic),
				Name:     "RSA-2048 public key",
				Key: &ftypes.CryptoKey{
					Size: 2048,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipUsedWith,
					RelatedAsset: rsaAlgorithm.Descriptor(),
				}},
			},
			wantAlgorithm: rsaAlgorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, algorithm, err := crypto.DescribeKey(tt.pub, tt.keyType, tt.format, tt.encoding)
			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantAlgorithm, algorithm)

			require.NoError(t, key.Validate())
			require.NoError(t, algorithm.Validate())
		})
	}
}

// TestDescribeKeyNoCanonicalForm covers the key of a certificate whose algorithm
// crypto/x509 does not recognize, which parsing leaves absent.
func TestDescribeKeyNoCanonicalForm(t *testing.T) {
	_, _, err := crypto.DescribeKey(nil, ftypes.CryptoKeyTypePublic, "", "")
	require.ErrorIs(t, err, crypto.ErrNoCanonicalForm)
}

func TestDescribeEncryptedKey(t *testing.T) {
	container := []byte("encrypted container")

	tests := []struct {
		name   string
		method ftypes.CryptoIdentityMethod
		format ftypes.CryptoKeyFormat
		want   ftypes.CryptoAssetInfo
	}{
		{
			name:   "PKCS#8",
			method: ftypes.CryptoMethodEncryptedPKCS8SHA256,
			format: ftypes.CryptoKeyFormatPKCS8,
			want: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePrivate,
				Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedPKCS8SHA256, container),
				Name:     "Encrypted PKCS#8 private key",
				Key: &ftypes.CryptoKey{
					Format:    ftypes.CryptoKeyFormatPKCS8,
					Encoding:  ftypes.CryptoEncodingPEM,
					Encrypted: true,
				},
			},
		},
		{
			name:   "RFC 1423",
			method: ftypes.CryptoMethodEncryptedRFC1423SHA256,
			format: ftypes.CryptoKeyFormatPKCS1,
			want: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindKey,
				KeyType:  ftypes.CryptoKeyTypePrivate,
				Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedRFC1423SHA256, container),
				Name:     "Encrypted PKCS#1 private key",
				Key: &ftypes.CryptoKey{
					Format:    ftypes.CryptoKeyFormatPKCS1,
					Encoding:  ftypes.CryptoEncodingPEM,
					Encrypted: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := crypto.DescribeEncryptedKey(tt.method, container, tt.format, ftypes.CryptoEncodingPEM)
			assert.Equal(t, tt.want, got)
			require.NoError(t, got.Validate())
		})
	}
}

func TestDescribeKeyIdentity(t *testing.T) {
	fixtures := newKeyFixtures(t)

	public, _, err := crypto.DescribeKey(fixtures.rsaPublic, ftypes.CryptoKeyTypePublic,
		ftypes.CryptoKeyFormatPKIX, ftypes.CryptoEncodingPEM)
	require.NoError(t, err)
	private, _, err := crypto.DescribeKey(fixtures.rsaPublic, ftypes.CryptoKeyTypePrivate,
		ftypes.CryptoKeyFormatPKCS8, ftypes.CryptoEncodingPEM)
	require.NoError(t, err)

	// The two are the same key material, and the key type is what keeps them apart.
	assert.Equal(t, public.Identity, private.Identity)
	assert.NotEqual(t, public.Descriptor(), private.Descriptor())
}

// TestMarshalPublicKey checks the encoding by reading the key back with crypto/x509, which
// parses every form produced here, including the DSA one it refuses to produce itself.
func TestMarshalPublicKey(t *testing.T) {
	fixtures := newKeyFixtures(t)

	tests := []struct {
		name    string
		pub     any
		wantErr string
	}{
		{
			name: "RSA",
			pub:  fixtures.rsaPublic,
		},
		{
			name: "ECDSA",
			pub:  fixtures.ecdsaPublic,
		},
		{
			name: "Ed25519",
			pub:  fixtures.ed25519Public,
		},
		{
			// The only key type encoded here rather than by crypto/x509.
			name: "DSA",
			pub:  fixtures.dsaPublic,
		},
		{
			name: "ML-DSA",
			pub:  fixtures.mldsaPublic,
		},
		{
			name:    "unsupported key type",
			pub:     "not a key",
			wantErr: "unsupported public key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := crypto.MarshalPublicKey(tt.pub)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			parsed, err := stdx509.ParsePKIXPublicKey(der)
			require.NoError(t, err)
			assert.Equal(t, tt.pub, parsed)
		})
	}
}

func newKeyFixtures(t *testing.T) keyFixtures {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ed25519Public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	return keyFixtures{
		rsaPublic:     &rsaKey.PublicKey,
		ecdsaPublic:   &ecdsaKey.PublicKey,
		ed25519Public: ed25519Public,
		mldsaPublic:   mldsaKey.PublicKey(),
		dsaPublic: &dsa.PublicKey{
			Parameters: dsa.Parameters{
				// A 2048-bit modulus, so that the reported key size is a realistic one.
				// The group is not a valid one, which nothing on this path checks.
				P: new(big.Int).Lsh(big.NewInt(1), 2047),
				Q: big.NewInt(11),
				G: big.NewInt(2),
			},
			Y: big.NewInt(4),
		},
	}
}

func spkiIdentity(t *testing.T, pub any) ftypes.CryptoIdentity {
	t.Helper()

	der, err := crypto.MarshalPublicKey(pub)
	require.NoError(t, err)

	return ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, der)
}
