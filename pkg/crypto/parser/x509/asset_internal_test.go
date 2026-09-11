package x509

import (
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := objectToAssets(t.Context(), tt.object)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
