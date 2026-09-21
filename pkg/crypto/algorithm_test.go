package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestDescribeAlgorithm(t *testing.T) {
	tests := []struct {
		name  string
		oid   string
		size  int
		curve string
		want  ftypes.CryptoAssetInfo
	}{
		{
			// A signature algorithm is described without key parameters, because the key
			// that produced the signature is not the one being described.
			name: "signature algorithm",
			oid:  "1.2.840.113549.1.1.11",
			want: ftypes.CryptoAssetInfo{
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
		},
		{
			// The catalog names the property that tells assets sharing an OID apart, and
			// the value of that property becomes part of the identity.
			name: "key size parameter",
			oid:  "1.2.840.113549.1.1.1",
			size: 2048,
			want: ftypes.CryptoAssetInfo{
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
			},
		},
		{
			name:  "curve parameter",
			oid:   "1.2.840.10045.2.1",
			size:  256,
			curve: "P-256",
			want: ftypes.CryptoAssetInfo{
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
		},
		{
			// RSASSA-PSS is left out of the catalog because its variants share one OID.
			name: "algorithm outside the catalog",
			oid:  "1.2.840.113549.1.1.10",
			want: ftypes.CryptoAssetInfo{
				Kind: ftypes.CryptoKindAlgorithm,
				Identity: ftypes.CryptoIdentity{
					Method: ftypes.CryptoMethodOID,
					Value:  "1.2.840.113549.1.1.10",
				},
				Name: "1.2.840.113549.1.1.10",
				Algorithm: &ftypes.CryptoAlgorithm{
					Primitive: ftypes.CryptoPrimitiveUnknown,
				},
			},
		},
		{
			// A catalog entry that names a parameter is described without it when the key
			// does not state one, which is what a signature algorithm does.
			name: "missing parameter value",
			oid:  "1.2.840.10045.2.1",
			want: ftypes.CryptoAssetInfo{
				Kind: ftypes.CryptoKindAlgorithm,
				Identity: ftypes.CryptoIdentity{
					Method: ftypes.CryptoMethodOID,
					Value:  "1.2.840.10045.2.1",
				},
				Name: "EC",
				Algorithm: &ftypes.CryptoAlgorithm{
					Primitive: ftypes.CryptoPrimitiveUnknown,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := crypto.DescribeAlgorithm(tt.oid, tt.size, tt.curve)
			assert.Equal(t, tt.want, got)
			require.NoError(t, got.Validate())
		})
	}
}
