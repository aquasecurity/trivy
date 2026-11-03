package x509_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cryptox509 "github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParseKeystoreObjects(t *testing.T) {
	encryptedDER, err := asn1.Marshal(cryptox509.EncryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2},
		EncryptedData: []byte{0x01, 0x02, 0x03},
	})
	require.NoError(t, err)

	encryptedKey := ftypes.CryptoAsset{
		CryptoAssetInfo: ftypes.CryptoAssetInfo{
			Kind:     ftypes.CryptoKindKey,
			KeyType:  ftypes.CryptoKeyTypePrivate,
			Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedPKCS8SHA256, encryptedDER),
			Name:     "Encrypted PKCS#8 private key",
			Key: &ftypes.CryptoKey{
				Encrypted: true,
			},
		},
		FilePath: parsedFilePath,
		Format:   ftypes.CryptoKeyFormatPKCS8,
		Encoding: ftypes.CryptoEncodingDER,
		Keystore: ftypes.CryptoKeystorePKCS12,
	}

	tests := []struct {
		name    string
		objects []cryptox509.KeystoreObject
		want    []ftypes.CryptoAsset
	}{
		{
			name: "encrypted private key",
			objects: []cryptox509.KeystoreObject{
				{Kind: cryptox509.KeystoreEncryptedPrivateKey, DER: encryptedDER},
			},
			want: []ftypes.CryptoAsset{encryptedKey},
		},
		{
			// An algorithm belongs to no keystore.
			name: "P-192 private key",
			objects: []cryptox509.KeystoreObject{
				{Kind: cryptox509.KeystorePrivateKey, DER: decodePEM(t, p192PKCS8PrivateKeyPEM)},
			},
			want: []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			// An algorithm belongs to no keystore.
			name: "P-192 certificate",
			objects: []cryptox509.KeystoreObject{
				{Kind: cryptox509.KeystoreCertificate, DER: decodePEM(t, p192CertificatePEM)},
			},
			want: []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name: "repeated object",
			objects: []cryptox509.KeystoreObject{
				{Kind: cryptox509.KeystoreEncryptedPrivateKey, DER: encryptedDER},
				{Kind: cryptox509.KeystoreEncryptedPrivateKey, DER: encryptedDER},
			},
			want: []ftypes.CryptoAsset{encryptedKey},
		},
		{
			name: "malformed object",
			objects: []cryptox509.KeystoreObject{
				{Kind: cryptox509.KeystorePrivateKey, DER: []byte{0x01}},
				{Kind: cryptox509.KeystoreEncryptedPrivateKey, DER: encryptedDER},
			},
			want: []ftypes.CryptoAsset{encryptedKey},
		},
		{
			name: "object without a kind",
			objects: []cryptox509.KeystoreObject{
				{DER: encryptedDER},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets, err := cryptox509.ParseKeystoreObjects(t.Context(), parsedFilePath, slices.Values(tt.objects), ftypes.CryptoKeystorePKCS12)
			require.NoError(t, err)
			checkAssets(t, assets)
			assert.Equal(t, tt.want, assets)
		})
	}
}
