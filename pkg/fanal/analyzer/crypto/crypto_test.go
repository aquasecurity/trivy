package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// assetSummary describes an asset by the fields that survive regenerating the key.
type assetSummary struct {
	kind     ftypes.CryptoKind
	keyType  ftypes.CryptoKeyType
	name     string
	encoding ftypes.CryptoEncoding
	keystore ftypes.CryptoKeystoreType
}

func Test_cryptoAnalyzer_Analyze(t *testing.T) {
	fixtures := newAnalyzerFixtures(t)

	tests := []struct {
		name     string
		filePath string
		content  []byte
		want     []assetSummary
	}{
		{
			name:     "PEM certificate",
			filePath: "etc/ssl/certs/server.pem",
			content:  fixtures.certificatePEM,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "example.test",
					encoding: ftypes.CryptoEncodingPEM,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "RSA-PKCS1-1.5-SHA-256",
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "RSA-2048 public key",
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "RSA-2048",
				},
			},
		},
		{
			name:     "PKCS#12 trust store",
			filePath: "usr/lib/jvm/java-21/lib/security/cacerts",
			content:  fixtures.truststore,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "cacerts.example.test",
					encoding: ftypes.CryptoEncodingDER,
					keystore: ftypes.CryptoKeystorePKCS12,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "ECDSA-SHA-384",
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "EC-P-256 public key",
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "EC-P-256",
				},
			},
		},
		{
			name:     "PKCS#12 keystore with the JKS extension",
			filePath: "certificates/server.jks",
			content:  fixtures.truststore,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "cacerts.example.test",
					encoding: ftypes.CryptoEncodingDER,
					keystore: ftypes.CryptoKeystorePKCS12,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "ECDSA-SHA-384",
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "EC-P-256 public key",
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "EC-P-256",
				},
			},
		},
		{
			name:     "Java keystore",
			filePath: "usr/lib/jvm/java-11/lib/security/cacerts",
			content:  []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02},
		},
		{
			name:     "Java cryptography extension keystore",
			filePath: "etc/app/keystore.jceks",
			content:  []byte{0xCE, 0xCE, 0xCE, 0xCE, 0x00, 0x00, 0x00, 0x02},
		},
		{
			name:     "BER encoding",
			filePath: "etc/app/keystore.p12",
			content:  []byte{0x30, 0x80, 0x02, 0x01, 0x03, 0x00, 0x00},
		},
		{
			name:     "PKCS#12 trust store without a keystore name",
			filePath: "etc/app/truststore",
			content:  fixtures.truststore,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "cacerts.example.test",
					encoding: ftypes.CryptoEncodingDER,
					keystore: ftypes.CryptoKeystorePKCS12,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "ECDSA-SHA-384",
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "EC-P-256 public key",
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "EC-P-256",
				},
			},
		},
		{
			name:     "PEM certificate named cacerts",
			filePath: "etc/app/cacerts",
			content:  fixtures.certificatePEM,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "example.test",
					encoding: ftypes.CryptoEncodingPEM,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "RSA-PKCS1-1.5-SHA-256",
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "RSA-2048 public key",
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "RSA-2048",
				},
			},
		},
		{
			name:     "no cryptographic object",
			filePath: "etc/ssl/certs/request.pem",
			content:  fixtures.certificateRequestPEM,
		},
		{
			name:     "content over the size limit",
			filePath: "etc/ssl/certs/server.pem",
			content:  slices.Concat(fixtures.certificatePEM, make([]byte, maxFileSize)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &cryptoAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  bytes.NewReader(tt.content),
			})
			require.NoError(t, err)

			if len(tt.want) == 0 {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want, summarize(got.CryptoAssets))

			for i, asset := range got.CryptoAssets {
				require.NoErrorf(t, asset.Validate(), "asset %d", i)
				assert.Equalf(t, tt.filePath, asset.FilePath, "asset %d", i)
				assert.Emptyf(t, asset.Layer, "asset %d", i)
			}
		})
	}
}

func summarize(assets []ftypes.CryptoAsset) []assetSummary {
	summaries := make([]assetSummary, 0, len(assets))
	for _, a := range assets {
		summaries = append(summaries, assetSummary{
			kind:     a.Kind,
			keyType:  a.KeyType,
			name:     a.Name,
			encoding: a.Encoding,
			keystore: a.Keystore,
		})
	}
	return summaries
}

// sizedFileInfo is an os.FileInfo of a given size.
type sizedFileInfo struct {
	os.FileInfo
	size int64
}

func (i sizedFileInfo) Size() int64 { return i.size }

func Test_cryptoAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		size     int64
		want     bool
	}{
		{name: "PEM extension", filePath: "certificates/server.pem", want: true},
		{name: "DER extension", filePath: "certificates/server.der", want: true},
		{name: "CRT extension", filePath: "certificates/server.crt", want: true},
		{name: "CER extension", filePath: "certificates/server.cer", want: true},
		{name: "KEY extension", filePath: "certificates/server.key", want: true},
		{name: "mixed-case extension", filePath: "certificates/server.CrT", want: true},
		{name: "public key extension", filePath: "certificates/server.pub"},
		{name: "P12 extension", filePath: "certificates/server.p12", want: true},
		{name: "PFX extension", filePath: "certificates/server.pfx", want: true},
		{name: "JKS extension", filePath: "certificates/server.jks", want: true},
		{name: "keystore extension", filePath: "certificates/server.keystore", want: true},
		{name: "mixed-case keystore extension", filePath: "certificates/server.P12", want: true},
		{name: "Java trust store", filePath: "usr/lib/jvm/java-21/lib/security/cacerts", want: true},
		{name: "Java trust store name as a suffix", filePath: "certificates/old-cacerts"},
		{name: "extensionless", filePath: "certificates/server"},
		{
			name:     "eligible extension within the size limit",
			filePath: "certificates/server.key",
			size:     maxFileSize,
			want:     true,
		},
		{
			name:     "eligible extension above the size limit",
			filePath: "certificates/server.key",
			size:     maxFileSize + 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &cryptoAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, sizedFileInfo{size: tt.size}))
		})
	}
}

type analyzerFixtures struct {
	certificatePEM        []byte
	certificateRequestPEM []byte
	truststore            []byte
}

func newAnalyzerFixtures(t *testing.T) analyzerFixtures {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certificateRequestDER, err := stdx509.CreateCertificateRequest(rand.Reader, &stdx509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.test"},
	}, rsaKey)
	require.NoError(t, err)

	// The trust store is generated from this directory.
	//
	//	docker run --rm -v "$PWD/testdata:/out" -w /tmp eclipse-temurin:21.0.12.1_1-jdk-alpine-3.24 sh -euc '
	//	keytool -genkeypair -alias cacerts -keyalg EC -groupname secp256r1 -dname CN=cacerts.example.test -validity 36500 -keystore key.p12 -storepass changeit
	//	keytool -exportcert -rfc -alias cacerts -keystore key.p12 -storepass changeit -file cacerts.pem
	//	keytool -importcert -noprompt -alias cacerts -file cacerts.pem -keystore /out/cacerts -storepass changeit -J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE -J-Dkeystore.pkcs12.macAlgorithm=NONE
	//	chmod 644 /out/cacerts
	//	'
	truststore, err := os.ReadFile("testdata/cacerts")
	require.NoError(t, err)

	return analyzerFixtures{
		certificatePEM:        encodePEM("CERTIFICATE", createCertificate(t, rsaKey)),
		certificateRequestPEM: encodePEM("CERTIFICATE REQUEST", certificateRequestDER),
		truststore:            truststore,
	}
}

func encodePEM(label string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  label,
		Bytes: der,
	})
}

func createCertificate(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()

	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              stdx509.KeyUsageCertSign,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}
