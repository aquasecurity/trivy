package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPublicKeyObjectMalformed covers keys whose public value does not fit their algorithm,
// which are malformed rather than unsupported.
func TestPublicKeyObjectMalformed(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{
			// crypto/x509 decodes Ed25519 and rejects the key.
			name: "Ed25519",
			oid:  asn1.ObjectIdentifier{1, 3, 101, 112},
		},
		{
			// crypto/x509 decodes X25519 and rejects the key.
			name: "X25519",
			oid:  asn1.ObjectIdentifier{1, 3, 101, 110},
		},
		{
			// crypto/x509 does not decode Ed448, and its OID fixes the key size.
			name: "Ed448",
			oid:  asn1.ObjectIdentifier{1, 3, 101, 113},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := asn1.Marshal(struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}{
				Algorithm:        pkix.AlgorithmIdentifier{Algorithm: tt.oid},
				SubjectPublicKey: asn1.BitString{Bytes: []byte{1}, BitLength: 8},
			})
			require.NoError(t, err)

			_, err = publicKeyObject(der)
			require.ErrorIs(t, err, errMalformedCrypto)
		})
	}
}
