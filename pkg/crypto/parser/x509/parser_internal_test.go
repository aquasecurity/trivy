package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrivateKeyObjectSize covers the bound on an RSA modulus. The keys carry only their
// leading fields, so crypto/x509 rejects those within the bound as malformed.
func TestPrivateKeyObjectSize(t *testing.T) {
	t.Parallel()

	pkcs1 := func(bits int) []byte {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		der, err := asn1.Marshal(rsaPrivateKeyHead{N: n})
		require.NoError(t, err)
		return der
	}
	pkcs8 := func(bits int) []byte {
		der, err := asn1.Marshal(pkcs8Head{
			Algo:       pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
			PrivateKey: pkcs1(bits),
		})
		require.NoError(t, err)
		return der
	}

	tests := []struct {
		name    string
		label   string
		der     []byte
		wantErr error
	}{
		{
			name:    "PKCS#1 within the bound",
			label:   "RSA PRIVATE KEY",
			der:     pkcs1(maxRSAModulusBits),
			wantErr: errMalformedCrypto,
		},
		{
			name:    "PKCS#1 over the bound",
			label:   "RSA PRIVATE KEY",
			der:     pkcs1(maxRSAModulusBits + 1),
			wantErr: errOversizedKey,
		},
		{
			name:    "PKCS#8 within the bound",
			label:   "PRIVATE KEY",
			der:     pkcs8(maxRSAModulusBits),
			wantErr: errMalformedCrypto,
		},
		{
			name:    "PKCS#8 over the bound",
			label:   "PRIVATE KEY",
			der:     pkcs8(maxRSAModulusBits + 1),
			wantErr: errOversizedKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parsePEMObject(tt.label, tt.der)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
