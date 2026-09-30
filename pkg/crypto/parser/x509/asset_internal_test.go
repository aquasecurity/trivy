package x509

import (
	stdx509 "crypto/x509"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// TestObjectToAssetsInvariants covers the branches that report a broken invariant of this
// package. Parsing produces no object that reaches them, so they are covered here rather
// than through Parse.
func TestObjectToAssetsInvariants(t *testing.T) {
	tests := []struct {
		name    string
		object  object
		wantErr string
	}{
		{
			name:    "object kind without a description",
			object:  object{},
			wantErr: "has no description",
		},
		{
			name: "encrypted private key without a container format",
			object: object{
				kind:      objectEncryptedPrivateKey,
				keyFormat: ftypes.CryptoKeyFormatPKCS8,
			},
			wantErr: "has no identification method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := objectToAssets(t.Context(), tt.object)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestObjectToAssetsWithUnknownKeyAlgorithm covers a certificate whose key is left out
// because crypto/x509 does not recognize its algorithm. The certificate keeps the rest of
// its description.
func TestObjectToAssetsWithUnknownKeyAlgorithm(t *testing.T) {
	signatureAlgorithm := ftypes.CryptoAssetInfo{
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
	}

	// crypto/x509 leaves PublicKey nil for a key algorithm it does not recognize.
	obj := object{
		kind: objectCertificate,
		certificate: certificate{
			Certificate:  &stdx509.Certificate{SerialNumber: big.NewInt(1)},
			signatureOID: "1.2.840.113549.1.1.11",
		},
		encoding: ftypes.CryptoEncodingPEM,
	}

	assets, err := objectToAssets(t.Context(), obj)
	require.NoError(t, err)

	// The certificate keeps the algorithm it is signed with and describes no key.
	want := []ftypes.CryptoAsset{
		{
			CryptoAssetInfo: ftypes.CryptoAssetInfo{
				Kind:     ftypes.CryptoKindCertificate,
				Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, nil),
				Certificate: &ftypes.CryptoCertificate{
					SerialNumber: "1",
					Format:       ftypes.CryptoCertificateFormatX509,
				},
				Relationships: []ftypes.CryptoRelationship{{
					Type:         ftypes.CryptoRelationshipSignedWith,
					RelatedAsset: signatureAlgorithm.Descriptor(),
				}},
			},
			Encoding: ftypes.CryptoEncodingPEM,
		},
		{CryptoAssetInfo: signatureAlgorithm},
	}
	assert.Equal(t, want, assets)
}
