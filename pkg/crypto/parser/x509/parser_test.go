package x509_test

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	cryptox509 "github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
)

var oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type parserFixtures struct {
	certificate    *stdx509.Certificate
	rsaPublic      *rsa.PublicKey
	ecdsaPublic    *ecdsa.PublicKey
	ed25519Public  ed25519.PublicKey
	dsaPublic      *dsa.PublicKey
	certificateDER []byte
	certificatePEM []byte
	pkcs1DER       []byte
	pkcs8DER       []byte
	pkcs8PEM       []byte
	sec1DER        []byte
	publicDER      []byte
	publicPEM      []byte
	encryptedDER   []byte
	encryptedPEM   []byte
	ed25519DER     []byte
	dsaDER         []byte
	x25519PKCS8DER []byte
	x25519PKIXDER  []byte
	csrDER         []byte
	csrPEM         []byte
	crlDER         []byte
	crlPEM         []byte
	unsupportedDER []byte
}

func TestParse(t *testing.T) {
	fixtures := newParserFixtures(t)
	encryptedDigest := sha256.Sum256(fixtures.encryptedDER)
	malformedPEMPrefix := append([]byte("-----BEGIN CERTIFICATE-----\nmalformed\n"), fixtures.certificatePEM...)

	tests := []struct {
		name  string
		input []byte
		want  []cryptox509.Object
	}{
		{
			name:  "certificate PEM",
			input: fixtures.certificatePEM,
			want: []cryptox509.Object{{
				Kind:        cryptox509.ObjectCertificate,
				Certificate: fixtures.certificate,
				Encoding:    crypto.EncodingPEM,
			}},
		},
		{
			name:  "certificate DER",
			input: fixtures.certificateDER,
			want: []cryptox509.Object{{
				Kind:        cryptox509.ObjectCertificate,
				Certificate: fixtures.certificate,
				Encoding:    crypto.EncodingDER,
			}},
		},
		{
			name:  "PKCS1 DER",
			input: fixtures.pkcs1DER,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPrivateKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  crypto.EncodingDER,
				KeyFormat: crypto.KeyFormatPKCS1,
			}},
		},
		{
			name:  "PKCS8 DER",
			input: fixtures.pkcs8DER,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPrivateKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  crypto.EncodingDER,
				KeyFormat: crypto.KeyFormatPKCS8,
			}},
		},
		{
			name:  "PKCS8 PEM",
			input: fixtures.pkcs8PEM,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPrivateKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  crypto.EncodingPEM,
				KeyFormat: crypto.KeyFormatPKCS8,
			}},
		},
		{
			name:  "SEC1 DER",
			input: fixtures.sec1DER,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPrivateKey,
				PublicKey: fixtures.ecdsaPublic,
				Encoding:  crypto.EncodingDER,
				KeyFormat: crypto.KeyFormatSEC1,
			}},
		},
		{
			name:  "PKIX public DER",
			input: fixtures.publicDER,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  crypto.EncodingDER,
				KeyFormat: crypto.KeyFormatPKIX,
			}},
		},
		{
			name:  "PKIX public PEM",
			input: fixtures.publicPEM,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  crypto.EncodingPEM,
				KeyFormat: crypto.KeyFormatPKIX,
			}},
		},
		{
			name:  "encrypted PKCS8 DER",
			input: fixtures.encryptedDER,
			want: []cryptox509.Object{{
				Kind:                 cryptox509.ObjectEncryptedPrivateKey,
				EncryptedPKCS8SHA256: hex.EncodeToString(encryptedDigest[:]),
				Encoding:             crypto.EncodingDER,
				KeyFormat:            crypto.KeyFormatPKCS8,
			}},
		},
		{
			name:  "encrypted PKCS8 PEM",
			input: fixtures.encryptedPEM,
			want: []cryptox509.Object{{
				Kind:                 cryptox509.ObjectEncryptedPrivateKey,
				EncryptedPKCS8SHA256: hex.EncodeToString(encryptedDigest[:]),
				Encoding:             crypto.EncodingPEM,
				KeyFormat:            crypto.KeyFormatPKCS8,
			}},
		},
		{
			name:  "Ed25519 PKCS8 DER",
			input: fixtures.ed25519DER,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPrivateKey,
				PublicKey: fixtures.ed25519Public,
				Encoding:  crypto.EncodingDER,
				KeyFormat: crypto.KeyFormatPKCS8,
			}},
		},
		{
			name:  "DSA PKIX DER",
			input: fixtures.dsaDER,
			want: []cryptox509.Object{{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.dsaPublic,
				Encoding:  crypto.EncodingDER,
				KeyFormat: crypto.KeyFormatPKIX,
			}},
		},
		{
			name:  "certificate bundle",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.certificatePEM}, nil),
			want: []cryptox509.Object{
				{
					Kind:        cryptox509.ObjectCertificate,
					Certificate: fixtures.certificate,
					Encoding:    crypto.EncodingPEM,
				},
				{
					Kind:        cryptox509.ObjectCertificate,
					Certificate: fixtures.certificate,
					Encoding:    crypto.EncodingPEM,
				},
			},
		},
		{
			name:  "certificate and private key",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.pkcs8PEM}, nil),
			want: []cryptox509.Object{
				{
					Kind:        cryptox509.ObjectCertificate,
					Certificate: fixtures.certificate,
					Encoding:    crypto.EncodingPEM,
				},
				{
					Kind:      cryptox509.ObjectPrivateKey,
					PublicKey: fixtures.rsaPublic,
					Encoding:  crypto.EncodingPEM,
					KeyFormat: crypto.KeyFormatPKCS8,
				},
			},
		},
		{
			name:  "malformed PEM followed by valid certificate",
			input: malformedPEMPrefix,
			want: []cryptox509.Object{{
				Kind:        cryptox509.ObjectCertificate,
				Certificate: fixtures.certificate,
				Encoding:    crypto.EncodingPEM,
			}},
		},
		{
			name:  "malformed supported PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x80}}),
		},
		{
			name:  "PKCS1 under PRIVATE KEY",
			input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: fixtures.pkcs1DER}),
		},
		{
			name:  "PKCS8 under RSA PRIVATE KEY",
			input: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: fixtures.pkcs8DER}),
		},
		{
			name:  "certificate request under CERTIFICATE",
			input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixtures.csrDER}),
		},
		{
			name:  "unsupported PKCS8 key under PRIVATE KEY",
			input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: fixtures.x25519PKCS8DER}),
		},
		{
			name:  "unsupported PKIX key under PUBLIC KEY",
			input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixtures.x25519PKIXDER}),
		},
		{
			name:  "unsupported X25519 DER",
			input: fixtures.x25519PKIXDER,
		},
		{
			name:  "certificate request PEM",
			input: fixtures.csrPEM,
		},
		{
			name:  "certificate request DER",
			input: fixtures.csrDER,
		},
		{
			name:  "malformed certificate request PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("malformed")}),
		},
		{
			name:  "certificate revocation list PEM",
			input: fixtures.crlPEM,
		},
		{
			name:  "certificate revocation list DER",
			input: fixtures.crlDER,
		},
		{
			name:  "malformed certificate revocation list PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("malformed")}),
		},
		{
			name:  "OpenSSH private key PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("opaque")}),
		},
		{
			name:  "unknown PEM label",
			input: pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN", Bytes: []byte("opaque")}),
		},
		{
			name:  "structurally malformed PEM",
			input: []byte("-----BEGIN CERTIFICATE-----\nmalformed\n"),
		},
		{
			name:  "complete unsupported ASN.1 sequence",
			input: fixtures.unsupportedDER,
		},
		{
			name:  "malformed ASN.1 sequence",
			input: []byte{0x30, 0x80},
		},
		{
			name:  "arbitrary bytes",
			input: []byte("arbitrary bytes"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, cryptox509.Parse(t.Context(), "candidate.pem", tt.input))
		})
	}
}

func newParserFixtures(t *testing.T) parserFixtures {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Self-signed certificate and CRL fixtures.
	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		SubjectKeyId:          []byte{0x01, 0x02, 0x03},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign | stdx509.KeyUsageDigitalSignature,
	}
	certificateDER, err := stdx509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	certificate, err := stdx509.ParseCertificate(certificateDER)
	require.NoError(t, err)
	crlDER, err := stdx509.CreateRevocationList(rand.Reader, &stdx509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Unix(1, 0),
		NextUpdate: time.Unix(2, 0),
	}, certificate, rsaKey)
	require.NoError(t, err)

	// Supported private and public key encodings.
	pkcs8DER, err := stdx509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	sec1DER, err := stdx509.MarshalECPrivateKey(ecdsaKey)
	require.NoError(t, err)
	publicDER, err := stdx509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed25519DER, err := stdx509.MarshalPKCS8PrivateKey(ed25519Private)
	require.NoError(t, err)
	dsaPublic := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: big.NewInt(23),
			Q: big.NewInt(11),
			G: big.NewInt(2),
		},
		Y: big.NewInt(4),
	}
	dsaDER := marshalDSAPublicKey(t, dsaPublic)

	// Opaque encrypted PKCS#8 container.
	encryptedDER, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2},
		EncryptedData: []byte{
			0x01, 0x02, 0x03,
		},
	})
	require.NoError(t, err)

	// Unsupported CSR and X25519 inputs.
	csrDER, err := stdx509.CreateCertificateRequest(rand.Reader, &stdx509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.test"},
	}, rsaKey)
	require.NoError(t, err)
	x25519Private, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	x25519PKCS8DER, err := stdx509.MarshalPKCS8PrivateKey(x25519Private)
	require.NoError(t, err)
	x25519PKIXDER, err := stdx509.MarshalPKIXPublicKey(x25519Private.PublicKey())
	require.NoError(t, err)
	unsupportedDER, err := asn1.Marshal(struct {
		Value string
	}{Value: "unsupported"})
	require.NoError(t, err)

	return parserFixtures{
		certificate:    certificate,
		rsaPublic:      &rsaKey.PublicKey,
		ecdsaPublic:    &ecdsaKey.PublicKey,
		ed25519Public:  ed25519Public,
		dsaPublic:      dsaPublic,
		certificateDER: certificateDER,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pkcs1DER:       stdx509.MarshalPKCS1PrivateKey(rsaKey),
		pkcs8DER:       pkcs8DER,
		pkcs8PEM:       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
		sec1DER:        sec1DER,
		publicDER:      publicDER,
		publicPEM:      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		encryptedDER:   encryptedDER,
		encryptedPEM:   pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER}),
		ed25519DER:     ed25519DER,
		dsaDER:         dsaDER,
		x25519PKCS8DER: x25519PKCS8DER,
		x25519PKIXDER:  x25519PKIXDER,
		csrDER:         csrDER,
		csrPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		crlDER:         crlDER,
		crlPEM:         pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}),
		unsupportedDER: unsupportedDER,
	}
}

func marshalDSAPublicKey(t *testing.T, publicKey *dsa.PublicKey) []byte {
	t.Helper()

	parameters, err := asn1.Marshal(struct {
		P *big.Int
		Q *big.Int
		G *big.Int
	}{
		P: publicKey.Parameters.P,
		Q: publicKey.Parameters.Q,
		G: publicKey.Parameters.G,
	})
	require.NoError(t, err)
	encodedPublicKey, err := asn1.Marshal(publicKey.Y)
	require.NoError(t, err)

	der, err := asn1.Marshal(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1},
			Parameters: asn1.RawValue{FullBytes: parameters},
		},
		SubjectPublicKey: asn1.BitString{Bytes: encodedPublicKey, BitLength: len(encodedPublicKey) * 8},
	})
	require.NoError(t, err)
	return der
}
