package pkcs12_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/pkcs12"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// parsedFilePath is the path every keystore is parsed from.
const parsedFilePath = "keystore.p12"

var (
	oidSecretBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	oidSDSICertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}
)

func TestParse(t *testing.T) {
	certificate := newCertificate(t, "example.test")
	other := newCertificate(t, "other.example.test")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8Key, err := stdx509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	sec1Key, err := stdx509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		content []byte
		want    []string
		wantErr error
	}{
		{
			name:    "OpenSSL keystore without a password",
			content: fixture(t, "openssl-no-password.p12"),
			want:    []string{"openssl-leaf.example.test", "openssl-ca.example.test"},
		},
		{
			name:    "keytool trust store without a password",
			content: fixture(t, "keytool-truststore.p12"),
			want:    []string{"keytool-first.example.test", "keytool-second.example.test"},
		},
		{
			name:    "keytool keystore with a password",
			content: fixture(t, "keytool-password.p12"),
		},
		{
			name:    "certificate",
			content: keystore(t, dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate)))),
			want:    []string{"example.test"},
		},
		{
			name: "repeated certificate",
			content: keystore(t,
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "nested safe contents at the depth limit",
			content: keystore(t, dataContent(t, safeContents(t,
				nest(t, 8, newCertBag(t, pkcs12.OIDX509Certificate, certificate)),
			))),
			want: []string{"example.test"},
		},
		{
			name: "nested safe contents over the depth limit",
			content: keystore(t, dataContent(t, safeContents(t,
				nest(t, 9, newCertBag(t, pkcs12.OIDX509Certificate, certificate)),
				newCertBag(t, pkcs12.OIDX509Certificate, other),
			))),
			want: []string{"other.example.test"},
		},
		{
			name: "bags at the limit",
			content: keystore(t, dataContent(t, safeContents(t, slices.Concat(
				[]pkcs12.SafeBag{newCertBag(t, pkcs12.OIDX509Certificate, certificate)},
				secretBags(t, pkcs12.MaxBags-3),
				[]pkcs12.SafeBag{newCertBag(t, pkcs12.OIDX509Certificate, other)},
			)...))),
			want: []string{"example.test", "other.example.test"},
		},
		{
			name: "bags over the limit",
			content: keystore(t, dataContent(t, safeContents(t, slices.Concat(
				[]pkcs12.SafeBag{newCertBag(t, pkcs12.OIDX509Certificate, certificate)},
				secretBags(t, pkcs12.MaxBags-2),
				[]pkcs12.SafeBag{newCertBag(t, pkcs12.OIDX509Certificate, other)},
			)...))),
			want: []string{"example.test"},
		},
		{
			name: "encrypted content",
			content: keystore(t,
				pkcs12.ContentInfo{ContentType: pkcs12.OIDEncryptedDataContentType, Content: explicit(marshal(t, []byte{0x01}))},
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "enveloped content",
			content: keystore(t,
				pkcs12.ContentInfo{ContentType: pkcs12.OIDEnvelopedDataContentType, Content: explicit(marshal(t, []byte{0x01}))},
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "content of an unsupported type",
			content: keystore(t,
				pkcs12.ContentInfo{ContentType: pkcs12.OIDSignedDataContentType, Content: explicit(marshal(t, 1))},
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "content that is not an OCTET STRING",
			content: keystore(t,
				pkcs12.ContentInfo{ContentType: pkcs12.OIDDataContentType, Content: explicit(marshal(t, 1))},
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "malformed safe contents",
			content: keystore(t,
				dataContent(t, marshal(t, 1)),
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "safe contents of indefinite length",
			content: keystore(t,
				dataContent(t, []byte{0x30, 0x80, 0x00, 0x00}),
				dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate))),
			),
			want: []string{"example.test"},
		},
		{
			name: "secret bag",
			content: keystore(t, dataContent(t, safeContents(t,
				pkcs12.SafeBag{ID: oidSecretBag, Value: explicit(marshal(t, []byte{0x01}))},
				newCertBag(t, pkcs12.OIDX509Certificate, certificate),
			))),
			want: []string{"example.test"},
		},
		{
			name: "SDSI certificate",
			content: keystore(t, dataContent(t, safeContents(t,
				newCertBag(t, oidSDSICertificate, []byte("sdsi")),
				newCertBag(t, pkcs12.OIDX509Certificate, certificate),
			))),
			want: []string{"example.test"},
		},
		{
			name: "malformed certificate",
			content: keystore(t, dataContent(t, safeContents(t,
				newCertBag(t, pkcs12.OIDX509Certificate, []byte("malformed")),
				newCertBag(t, pkcs12.OIDX509Certificate, certificate),
			))),
			want: []string{"example.test"},
		},
		{
			name: "authenticated safe signed with a public key",
			content: marshal(t, pkcs12.PFX{
				Version:  3,
				AuthSafe: pkcs12.ContentInfo{ContentType: pkcs12.OIDSignedDataContentType, Content: explicit(marshal(t, 1))},
			}),
		},
		{
			name: "authenticated safe of an unsupported type",
			content: marshal(t, pkcs12.PFX{
				Version:  3,
				AuthSafe: pkcs12.ContentInfo{ContentType: pkcs12.OIDEncryptedDataContentType, Content: explicit(marshal(t, 1))},
			}),
		},
		{
			name: "unsupported version",
			content: marshal(t, pkcs12.PFX{
				Version:  2,
				AuthSafe: dataContent(t, marshal(t, []pkcs12.ContentInfo{dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate)))})),
			}),
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "trailing data",
			content: append(keystore(t, dataContent(t, safeContents(t, newCertBag(t, pkcs12.OIDX509Certificate, certificate)))), 0x00),
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "indefinite length",
			content: []byte{0x30, 0x80, 0x02, 0x01, 0x03, 0x00, 0x00},
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "Java keystore",
			content: []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02},
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "DER certificate",
			content: certificate,
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "PEM certificate",
			content: []byte("-----BEGIN CERTIFICATE-----\n"),
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "DER PKCS#1 private key",
			content: stdx509.MarshalPKCS1PrivateKey(rsaKey),
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "DER PKCS#8 private key",
			content: pkcs8Key,
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "DER SEC1 private key",
			content: sec1Key,
			wantErr: pkcs12.ErrNotPKCS12,
		},
		{
			name:    "empty file",
			wantErr: pkcs12.ErrNotPKCS12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets, err := pkcs12.Parse(t.Context(), parsedFilePath, tt.content)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, certificateNames(t, assets))
		})
	}
}

// certificateNames checks that every asset is valid and not a private key, and returns the
// names of the certificates among them.
func certificateNames(t *testing.T, assets []ftypes.CryptoAsset) []string {
	t.Helper()

	var names []string
	for i, asset := range assets {
		require.NoErrorf(t, asset.Validate(), "asset %d", i)
		assert.Equalf(t, parsedFilePath, asset.FilePath, "asset %d", i)
		assert.NotEqualf(t, ftypes.CryptoKeyTypePrivate, asset.KeyType, "asset %d", i)
		if asset.Kind != ftypes.CryptoKindCertificate {
			continue
		}
		assert.Equalf(t, ftypes.CryptoEncodingDER, asset.Encoding, "asset %d", i)
		assert.Equalf(t, ftypes.CryptoKeystorePKCS12, asset.Keystore, "asset %d", i)
		names = append(names, asset.Name)
	}
	return names
}

// fixture reads a keystore from testdata. The keystores are generated from this directory.
//
//	docker run --rm --entrypoint sh -v "$PWD/testdata:/out" -w /tmp alpine/openssl:3.5.9 -euc '
//	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout ca.key -out ca.pem -subj /CN=openssl-ca.example.test -days 36500
//	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout leaf.key -out leaf.csr -subj /CN=openssl-leaf.example.test
//	openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 2 -days 36500 -out leaf.pem
//	openssl pkcs12 -export -in leaf.pem -inkey leaf.key -certfile ca.pem -certpbe NONE -keypbe NONE -nomac -passout pass: -out /out/openssl-no-password.p12
//	chmod 644 /out/openssl-no-password.p12
//	'
//
//	docker run --rm -v "$PWD/testdata:/out" -w /tmp eclipse-temurin:21.0.12.1_1-jdk-alpine-3.24 sh -euc '
//	for name in first second; do
//	  keytool -genkeypair -alias $name -keyalg EC -groupname secp256r1 -dname CN=keytool-$name.example.test -validity 36500 -keystore $name.p12 -storepass changeit
//	  keytool -exportcert -rfc -alias $name -keystore $name.p12 -storepass changeit -file $name.pem
//	  keytool -importcert -noprompt -alias $name -file $name.pem -keystore /out/keytool-truststore.p12 -storepass changeit -J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE -J-Dkeystore.pkcs12.macAlgorithm=NONE
//	done
//	cp first.p12 /out/keytool-password.p12
//	chmod 644 /out/keytool-*.p12
//	'
func fixture(t *testing.T, name string) []byte {
	t.Helper()

	content, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return content
}

// keystore stores contents in a PKCS#12 file with no integrity mode.
func keystore(t *testing.T, contents ...pkcs12.ContentInfo) []byte {
	t.Helper()

	return marshal(t, pkcs12.PFX{
		Version:  3,
		AuthSafe: dataContent(t, marshal(t, contents)),
	})
}

// dataContent stores der as a content of the data type.
func dataContent(t *testing.T, der []byte) pkcs12.ContentInfo {
	t.Helper()

	return pkcs12.ContentInfo{
		ContentType: pkcs12.OIDDataContentType,
		Content:     explicit(marshal(t, der)),
	}
}

func safeContents(t *testing.T, bags ...pkcs12.SafeBag) []byte {
	t.Helper()

	return marshal(t, bags)
}

func newCertBag(t *testing.T, certType asn1.ObjectIdentifier, der []byte) pkcs12.SafeBag {
	t.Helper()

	return pkcs12.SafeBag{
		ID: pkcs12.OIDCertBag,
		Value: explicit(marshal(t, pkcs12.CertBag{
			ID:   certType,
			Data: der,
		})),
	}
}

func secretBags(t *testing.T, n int) []pkcs12.SafeBag {
	t.Helper()

	bag := pkcs12.SafeBag{ID: oidSecretBag, Value: explicit(marshal(t, []byte{0x01}))}
	return slices.Repeat([]pkcs12.SafeBag{bag}, n)
}

// nest puts bag into the given number of nested safe contents bags.
func nest(t *testing.T, depth int, bag pkcs12.SafeBag) pkcs12.SafeBag {
	t.Helper()

	for range depth {
		bag = pkcs12.SafeBag{
			ID:    pkcs12.OIDSafeContentsBag,
			Value: explicit(safeContents(t, bag)),
		}
	}
	return bag
}

// explicit wraps der in the [0] EXPLICIT tag of a content or a bag value, which asn1.Marshal
// does not add to a RawValue field.
func explicit(der []byte) asn1.RawValue {
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      der,
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()

	der, err := asn1.Marshal(v)
	require.NoError(t, err)
	return der
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
