package x509

import (
	stdx509 "crypto/x509"
	"math/big"
	"testing"

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
		{
			name: "certificate without a key",
			object: object{
				kind: objectCertificate,
				certificate: certificate{
					Certificate: &stdx509.Certificate{SerialNumber: big.NewInt(1)},
				},
			},
			wantErr: "describe certificate key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := objectToAssets(tt.object)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
