package jks_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/jks"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// parsedFilePath is the path every keystore is parsed from.
const parsedFilePath = "keystore.jks"

func TestParse(t *testing.T) {
	certificate := newCertificate(t, "example.test")
	other := newCertificate(t, "other.example.test")

	// The last 30 bytes are the 20-byte integrity hash and the end of the second certificate.
	truncated := keystore(2,
		trustedCertEntry(2, "X.509", certificate),
		trustedCertEntry(2, "X.509", other),
	)
	truncated = truncated[:len(truncated)-30]

	tests := []struct {
		name    string
		content []byte
		want    []string
		wantErr error
	}{
		{
			name:    "keytool trust store",
			content: fixture(t, "keytool-truststore.jks"),
			want:    []string{"keytool-second.example.test", "keytool-first.example.test"},
		},
		{
			name:    "keytool keystore with a private key",
			content: fixture(t, "keytool-keystore.jks"),
			want:    []string{"keytool-key.example.test"},
		},
		{
			name:    "version 1",
			content: keystore(1, trustedCertEntry(1, "X.509", certificate)),
			want:    []string{"example.test"},
		},
		{
			name:    "private key with a chain",
			content: keystore(2, privateKeyEntry(2, []byte{0x01}, certificate, other)),
			want:    []string{"example.test", "other.example.test"},
		},
		{
			name: "repeated certificate",
			content: keystore(2,
				privateKeyEntry(2, []byte{0x01}, certificate),
				trustedCertEntry(2, "X.509", certificate),
			),
			want: []string{"example.test"},
		},
		{
			name: "certificate of another type",
			content: keystore(2,
				trustedCertEntry(2, "PGP", []byte{0x01}),
				trustedCertEntry(2, "X.509", certificate),
			),
			want: []string{"example.test"},
		},
		{
			name: "malformed certificate",
			content: keystore(2,
				trustedCertEntry(2, "X.509", []byte("malformed")),
				trustedCertEntry(2, "X.509", certificate),
			),
			want: []string{"example.test"},
		},
		{
			name:    "truncated entry",
			content: truncated,
			want:    []string{"example.test"},
		},
		{
			name: "unknown entry tag",
			content: keystore(2,
				trustedCertEntry(2, "X.509", certificate),
				entry(3, func(*cryptobyte.Builder) {}),
				trustedCertEntry(2, "X.509", other),
			),
			want: []string{"example.test"},
		},
		{
			name:    "unsupported version",
			content: keystore(3, trustedCertEntry(2, "X.509", certificate)),
		},
		{
			name: "private key longer than the file",
			content: keystore(2,
				trustedCertEntry(2, "X.509", certificate),
				entry(1, func(b *cryptobyte.Builder) {
					b.AddUint32(1000)
					b.AddBytes([]byte{0x01})
				}),
				trustedCertEntry(2, "X.509", other),
			),
			want: []string{"example.test"},
		},
		{
			name:    "JCEKS keystore",
			content: []byte{0xCE, 0xCE, 0xCE, 0xCE, 0x00, 0x00, 0x00, 0x02},
			wantErr: jks.ErrNotJKS,
		},
		{
			name:    "empty file",
			wantErr: jks.ErrNotJKS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets, err := jks.Parse(t.Context(), parsedFilePath, tt.content)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, certificateNames(t, assets))
		})
	}
}

// certificateNames checks that every asset is valid and returns the names of the
// certificates among them.
func certificateNames(t *testing.T, assets []ftypes.CryptoAsset) []string {
	t.Helper()

	var names []string
	for i, asset := range assets {
		require.NoErrorf(t, asset.Validate(), "asset %d", i)
		assert.Equalf(t, parsedFilePath, asset.FilePath, "asset %d", i)
		if asset.Kind != ftypes.CryptoKindCertificate {
			continue
		}
		assert.Equalf(t, ftypes.CryptoEncodingDER, asset.Encoding, "asset %d", i)
		assert.Equalf(t, ftypes.CryptoKeystoreJKS, asset.Keystore, "asset %d", i)
		names = append(names, asset.Name)
	}
	return names
}

// fixture reads a keystore from testdata. The keystores are generated from this directory.
//
//	docker run --rm -v "$PWD/testdata:/out" -w /tmp eclipse-temurin:21.0.12.1_1-jdk-alpine-3.24 sh -euc '
//	keytool -genkeypair -alias key -keyalg EC -groupname secp256r1 -dname CN=keytool-key.example.test -validity 36500 -storetype JKS -keystore /out/keytool-keystore.jks -storepass changeit -keypass changeit
//	for name in first second; do
//	  keytool -genkeypair -alias $name -keyalg EC -groupname secp256r1 -dname CN=keytool-$name.example.test -validity 36500 -keystore $name.p12 -storepass changeit
//	  keytool -exportcert -rfc -alias $name -keystore $name.p12 -storepass changeit -file $name.pem
//	  keytool -importcert -noprompt -alias $name -file $name.pem -storetype JKS -keystore /out/keytool-truststore.jks -storepass changeit
//	done
//	chmod 644 /out/*.jks
//	'
func fixture(t *testing.T, name string) []byte {
	t.Helper()

	content, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return content
}

// keystore stores entries in a JKS file with a zeroed integrity hash.
func keystore(version uint32, entries ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddUint32(0xFEEDFEED)
	b.AddUint32(version)
	b.AddUint32(uint32(len(entries)))
	for _, e := range entries {
		b.AddBytes(e)
	}
	b.AddBytes(make([]byte, 20))
	return b.BytesOrPanic()
}

func entry(tag uint32, body func(*cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	b.AddUint32(tag)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("alias"))
	})
	b.AddUint64(0)
	body(&b)
	return b.BytesOrPanic()
}

func trustedCertEntry(version uint32, certType string, der []byte) []byte {
	return entry(2, func(b *cryptobyte.Builder) {
		addCertificate(b, version, certType, der)
	})
}

func privateKeyEntry(version uint32, encryptedKey []byte, chain ...[]byte) []byte {
	return entry(1, func(b *cryptobyte.Builder) {
		b.AddUint32(uint32(len(encryptedKey)))
		b.AddBytes(encryptedKey)
		b.AddUint32(uint32(len(chain)))
		for _, der := range chain {
			addCertificate(b, version, "X.509", der)
		}
	})
}

// addCertificate writes a certificate, which states its type only in version 2.
func addCertificate(b *cryptobyte.Builder, version uint32, certType string, der []byte) {
	if version == 2 {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(certType))
		})
	}
	b.AddUint32(uint32(len(der)))
	b.AddBytes(der)
}

func newCertificate(t *testing.T, commonName string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}
