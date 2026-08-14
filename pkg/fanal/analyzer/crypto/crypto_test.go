package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// assetSummary holds the fields of a CryptoAsset that do not depend on the generated
// material, so that a case can state its expectation without a digest.
type assetSummary struct {
	kind     ftypes.CryptoKind
	keyType  ftypes.CryptoKeyType
	name     string
	format   ftypes.CryptoKeyFormat
	encoding ftypes.CryptoEncoding
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
			name:     "DER certificate",
			filePath: "etc/ssl/certs/server.der",
			content:  fixtures.certificateDER,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "example.test",
					encoding: ftypes.CryptoEncodingDER,
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
			// The certificates share their signature algorithm and their key algorithm,
			// which the bundle reports once.
			name:     "certificate bundle",
			filePath: "etc/ssl/certs/ca-bundle.crt",
			content:  slices.Concat(fixtures.certificatePEM, fixtures.otherCertificatePEM),
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
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "other.test",
					encoding: ftypes.CryptoEncodingPEM,
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "RSA-2048 public key",
				},
			},
		},
		{
			// The key of the certificate and the standalone key are the same key, so the
			// file reports one key asset, described by its own container.
			name:     "certificate and its public key",
			filePath: "etc/ssl/certs/server.pem",
			content:  slices.Concat(fixtures.certificatePEM, fixtures.publicKeyPEM),
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
					kind:     ftypes.CryptoKindKey,
					keyType:  ftypes.CryptoKeyTypePublic,
					name:     "RSA-2048 public key",
					format:   ftypes.CryptoKeyFormatPKIX,
					encoding: ftypes.CryptoEncodingPEM,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "RSA-2048",
				},
			},
		},
		{
			// Ed25519 identifies the signature algorithm and the key algorithm by one OID.
			name:     "Ed25519 certificate",
			filePath: "etc/ssl/certs/ed25519.pem",
			content:  fixtures.ed25519CertificatePEM,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindCertificate,
					name:     "example.test",
					encoding: ftypes.CryptoEncodingPEM,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "Ed25519",
				},
				{
					kind:    ftypes.CryptoKindKey,
					keyType: ftypes.CryptoKeyTypePublic,
					name:    "Ed25519 public key",
				},
			},
		},
		{
			name:     "private key",
			filePath: "etc/ssl/private/server.key",
			content:  fixtures.privateKeyPEM,
			want: []assetSummary{
				{
					kind:     ftypes.CryptoKindKey,
					keyType:  ftypes.CryptoKeyTypePrivate,
					name:     "RSA-2048 private key",
					format:   ftypes.CryptoKeyFormatPKCS8,
					encoding: ftypes.CryptoEncodingPEM,
				},
				{
					kind: ftypes.CryptoKindAlgorithm,
					name: "RSA-2048",
				},
			},
		},
		{
			name:     "unsupported object",
			filePath: "etc/ssl/certs/request.pem",
			content:  fixtures.certificateRequestPEM,
		},
		{
			name:     "no cryptographic object",
			filePath: "etc/ssl/certs/notes.pem",
			content:  []byte("no cryptographic material here"),
		},
		{
			name:     "empty file",
			filePath: "etc/ssl/certs/empty.pem",
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

			descriptors := set.New[ftypes.CryptoDescriptor]()
			for i, asset := range got.CryptoAssets {
				require.NoErrorf(t, asset.Validate(), "asset %d", i)
				assert.Equalf(t, tt.filePath, asset.FilePath, "asset %d", i)
				assert.Emptyf(t, asset.Layer, "asset %d", i)
				descriptors.Append(asset.Descriptor())
			}
			assert.Equal(t, len(got.CryptoAssets), descriptors.Size(), "assets share an identity")

			for i, asset := range got.CryptoAssets {
				for j, relationship := range asset.Relationships {
					assert.Truef(t, descriptors.Contains(relationship.RelatedAsset),
						"asset %d refers to a missing asset %q in relationship %d", i, relationship.RelatedAsset, j)
				}
			}
		})
	}
}

func summarize(assets []ftypes.CryptoAsset) []assetSummary {
	summaries := make([]assetSummary, 0, len(assets))
	for _, a := range assets {
		summary := assetSummary{
			kind:    a.Kind,
			keyType: a.KeyType,
			name:    a.Name,
		}
		switch {
		case a.Certificate != nil:
			summary.encoding = a.Certificate.Encoding
		case a.Key != nil:
			summary.format = a.Key.Format
			summary.encoding = a.Key.Encoding
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func Test_cryptoAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "PEM extension", filePath: "certificates/server.pem", want: true},
		{name: "DER extension", filePath: "certificates/server.der", want: true},
		{name: "CRT extension", filePath: "certificates/server.crt", want: true},
		{name: "CER extension", filePath: "certificates/server.cer", want: true},
		{name: "KEY extension", filePath: "certificates/server.key", want: true},
		{name: "mixed-case extension", filePath: "certificates/server.CrT", want: true},
		{name: "public key extension", filePath: "certificates/server.pub"},
		{name: "PKCS12 extension", filePath: "certificates/server.p12"},
		{name: "extensionless", filePath: "certificates/server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &cryptoAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}

type analyzerFixtures struct {
	certificateDER        []byte
	certificatePEM        []byte
	otherCertificatePEM   []byte
	ed25519CertificatePEM []byte
	privateKeyPEM         []byte
	publicKeyPEM          []byte
	certificateRequestPEM []byte
}

func newAnalyzerFixtures(t *testing.T) analyzerFixtures {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	certificateDER := createCertificate(t, "example.test", &rsaKey.PublicKey, rsaKey)
	privateKeyDER, err := stdx509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	publicKeyDER, err := stdx509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	certificateRequestDER, err := stdx509.CreateCertificateRequest(rand.Reader, &stdx509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.test"},
	}, rsaKey)
	require.NoError(t, err)

	return analyzerFixtures{
		certificateDER:        certificateDER,
		certificatePEM:        encodePEM("CERTIFICATE", certificateDER),
		otherCertificatePEM:   encodePEM("CERTIFICATE", createCertificate(t, "other.test", &otherRSAKey.PublicKey, otherRSAKey)),
		ed25519CertificatePEM: encodePEM("CERTIFICATE", createCertificate(t, "example.test", ed25519Public, ed25519Private)),
		privateKeyPEM:         encodePEM("PRIVATE KEY", privateKeyDER),
		publicKeyPEM:          encodePEM("PUBLIC KEY", publicKeyDER),
		certificateRequestPEM: encodePEM("CERTIFICATE REQUEST", certificateRequestDER),
	}
}

func encodePEM(label string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  label,
		Bytes: der,
	})
}

func createCertificate(t *testing.T, commonName string, publicKey, privateKey any) []byte {
	t.Helper()

	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              stdx509.KeyUsageCertSign,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	return der
}
