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
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	cryptox509 "github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

// encryptedPrivateKeyInfo is the RFC 5958 envelope, which the parser validates without
// opening.
type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

// found states what an input was recognized as.
type found struct {
	kind     ftypes.CryptoKind
	keyType  ftypes.CryptoKeyType
	method   ftypes.CryptoIdentityMethod
	format   ftypes.CryptoKeyFormat
	encoding ftypes.CryptoEncoding
}

func TestParse(t *testing.T) {
	fixtures := newFixtures(t)
	malformedPEMPrefix := append([]byte("-----BEGIN CERTIFICATE-----\nmalformed\n"), fixtures.certificatePEM...)
	rfc1423Headers := map[string]string{
		"Proc-Type": "4,ENCRYPTED",
		"DEK-Info":  "AES-256-CBC,00112233445566778899AABBCCDDEEFF",
	}
	rfc1423Ciphertext := []byte{0x01, 0x02, 0x03, 0x04}

	pemCertificate := found{
		kind:     ftypes.CryptoKindCertificate,
		method:   ftypes.CryptoMethodSHA256,
		encoding: ftypes.CryptoEncodingPEM,
	}
	// Every certificate also describes the key it carries, which has no container of its own.
	certificateKey := found{
		kind:    ftypes.CryptoKindKey,
		keyType: ftypes.CryptoKeyTypePublic,
		method:  ftypes.CryptoMethodSPKISHA256,
	}

	tests := []struct {
		name  string
		input []byte
		want  []found
	}{
		{
			name:  "certificate PEM",
			input: fixtures.certificatePEM,
			want: []found{
				pemCertificate,
				certificateKey,
			},
		},
		{
			name:  "certificate DER",
			input: fixtures.certificateDER,
			want: []found{
				{
					kind:     ftypes.CryptoKindCertificate,
					method:   ftypes.CryptoMethodSHA256,
					encoding: ftypes.CryptoEncodingDER,
				},
				certificateKey,
			},
		},
		{
			name:  "PKCS1 DER",
			input: fixtures.pkcs1DER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKCS1,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "PKCS8 DER",
			input: fixtures.pkcs8DER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKCS8,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "PKCS8 PEM",
			input: fixtures.pkcs8PEM,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKCS8,
				encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			name:  "SEC1 DER",
			input: fixtures.sec1DER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatSEC1,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "PKIX public DER",
			input: fixtures.publicDER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePublic,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKIX,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "PKIX public PEM",
			input: fixtures.publicPEM,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePublic,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKIX,
				encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			name:  "encrypted PKCS8 DER",
			input: fixtures.encryptedDER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodEncryptedPKCS8SHA256,
				format:   ftypes.CryptoKeyFormatPKCS8,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "encrypted PKCS8 PEM",
			input: fixtures.encryptedPEM,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodEncryptedPKCS8SHA256,
				format:   ftypes.CryptoKeyFormatPKCS8,
				encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			// An RFC 1423 container states its key format in the PEM label, because the
			// encrypted payload cannot be read.
			name:  "RFC 1423 encrypted RSA private key",
			input: fixtures.rfc1423PEM,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodEncryptedRFC1423SHA256,
				format:   ftypes.CryptoKeyFormatPKCS1,
				encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			name: "RFC 1423 encrypted EC private key",
			input: pem.EncodeToMemory(&pem.Block{
				Type:    "EC PRIVATE KEY",
				Headers: rfc1423Headers,
				Bytes:   rfc1423Ciphertext,
			}),
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodEncryptedRFC1423SHA256,
				format:   ftypes.CryptoKeyFormatSEC1,
				encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			name: "RFC 1423 encrypted PKCS8 private key",
			input: pem.EncodeToMemory(&pem.Block{
				Type:    "PRIVATE KEY",
				Headers: rfc1423Headers,
				Bytes:   rfc1423Ciphertext,
			}),
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodEncryptedRFC1423SHA256,
				format:   ftypes.CryptoKeyFormatPKCS8,
				encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			name:  "Ed25519 PKCS8 DER",
			input: fixtures.ed25519DER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKCS8,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "DSA PKIX DER",
			input: fixtures.dsaDER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePublic,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKIX,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "certificate bundle",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.certificatePEM}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
				pemCertificate,
				certificateKey,
			},
		},
		{
			name:  "certificate and private key",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.pkcs8PEM}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
				{
					kind:     ftypes.CryptoKindKey,
					keyType:  ftypes.CryptoKeyTypePrivate,
					method:   ftypes.CryptoMethodSPKISHA256,
					format:   ftypes.CryptoKeyFormatPKCS8,
					encoding: ftypes.CryptoEncodingPEM,
				},
			},
		},
		{
			name:  "malformed PEM followed by valid certificate",
			input: malformedPEMPrefix,
			want: []found{
				pemCertificate,
				certificateKey,
			},
		},
		{
			name:  "malformed supported PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x80}}),
		},
		{
			name: "RFC 1423 missing Proc-Type",
			input: pem.EncodeToMemory(&pem.Block{
				Type:    "RSA PRIVATE KEY",
				Headers: map[string]string{"DEK-Info": rfc1423Headers["DEK-Info"]},
				Bytes:   rfc1423Ciphertext,
			}),
		},
		{
			name: "RFC 1423 missing DEK-Info",
			input: pem.EncodeToMemory(&pem.Block{
				Type:    "RSA PRIVATE KEY",
				Headers: map[string]string{"Proc-Type": rfc1423Headers["Proc-Type"]},
				Bytes:   rfc1423Ciphertext,
			}),
		},
		{
			name: "RFC 1423 missing ciphertext",
			input: pem.EncodeToMemory(&pem.Block{
				Type:    "RSA PRIVATE KEY",
				Headers: rfc1423Headers,
			}),
		},
		{
			name: "RFC 1423 unsupported key label",
			input: pem.EncodeToMemory(&pem.Block{
				Type:    "DSA PRIVATE KEY",
				Headers: rfc1423Headers,
				Bytes:   rfc1423Ciphertext,
			}),
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
			assets := parse(t, tt.input)
			assert.Equal(t, tt.want, recognized(assets))
		})
	}
}

func TestParseAssets(t *testing.T) {
	fixtures := newFixtures(t)

	// The algorithm of an RSA key cannot be told apart from a signature algorithm by its
	// OID alone, so it carries an unknown primitive and no family.
	rsaAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.113549.1.1.1",
			Parameters: "key-size=2048",
		},
		Name: "RSA-2048",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	signatureAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.2.840.113549.1.1.11",
		},
		Name: "RSA-PKCS1-1.5-SHA-256",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "RSASSA-PKCS1",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}

	// The key a certificate carries has no format and no encoding of its own.
	certificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: spkiIdentity(t, fixtures.rsaPublic),
		Name:     "RSA-2048 public key",
		Key: &ftypes.CryptoKey{
			Size: 2048,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: rsaAlgorithm.Descriptor(),
		}},
	}

	tests := []struct {
		name  string
		input []byte
		want  []ftypes.CryptoAssetInfo
	}{
		{
			name:  "certificate",
			input: fixtures.certificatePEM,
			want: []ftypes.CryptoAssetInfo{
				{
					Kind:     ftypes.CryptoKindCertificate,
					Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.certificate.Raw),
					Name:     "example.test",
					Certificate: &ftypes.CryptoCertificate{
						Subject:      "CN=example.test",
						Issuer:       "CN=example.test",
						SerialNumber: "123456789",
						// A parsed certificate reports its validity period in UTC.
						NotBefore: time.Unix(1, 0).UTC(),
						NotAfter:  time.Unix(2, 0).UTC(),
						Format:    ftypes.CryptoCertificateFormatX509,
						Encoding:  ftypes.CryptoEncodingPEM,
						KeyUsage: []string{
							"digitalSignature",
							"keyEncipherment",
							"keyCertSign",
							"cRLSign",
						},
						// Recognized usages are named by crypto/x509, the rest by OID.
						ExtendedKeyUsage: []string{
							"serverAuth",
							"clientAuth",
							"1.3.6.1.4.1.311.20.2.2",
						},
						DNSNames:       []string{"example.test", "www.example.test"},
						EmailAddresses: []string{"admin@example.test"},
						IPAddresses:    []string{"192.0.2.1"},
						URIs:           []string{"spiffe://example.test/workload"},

						BasicConstraintsValid: true,
						IsCA:                  true,
						// The certificate carries no path length, which crypto/x509 reports as -1.
						MaxPathLen:     0,
						MaxPathLenZero: false,
					},
					Relationships: []ftypes.CryptoRelationship{
						{
							Type:         ftypes.CryptoRelationshipSignedWith,
							RelatedAsset: signatureAlgorithm.Descriptor(),
						},
						{
							Type:         ftypes.CryptoRelationshipContains,
							RelatedAsset: certificateKey.Descriptor(),
						},
					},
				},
				signatureAlgorithm,
				certificateKey,
				rsaAlgorithm,
			},
		},
		{
			// A standalone key states the container it was found in, which the key of a
			// certificate has no equivalent of.
			name:  "public key",
			input: fixtures.publicPEM,
			want: []ftypes.CryptoAssetInfo{
				{
					Kind:     ftypes.CryptoKindKey,
					KeyType:  ftypes.CryptoKeyTypePublic,
					Identity: spkiIdentity(t, fixtures.rsaPublic),
					Name:     "RSA-2048 public key",
					Key: &ftypes.CryptoKey{
						Size:     2048,
						Format:   ftypes.CryptoKeyFormatPKIX,
						Encoding: ftypes.CryptoEncodingPEM,
					},
					Relationships: []ftypes.CryptoRelationship{{
						Type:         ftypes.CryptoRelationshipUsedWith,
						RelatedAsset: rsaAlgorithm.Descriptor(),
					}},
				},
				rsaAlgorithm,
			},
		},
		{
			// The parser projects a private key to its public part, so only the key type differs.
			name:  "private key",
			input: fixtures.pkcs8PEM,
			want: []ftypes.CryptoAssetInfo{
				{
					Kind:     ftypes.CryptoKindKey,
					KeyType:  ftypes.CryptoKeyTypePrivate,
					Identity: spkiIdentity(t, fixtures.rsaPublic),
					Name:     "RSA-2048 private key",
					Key: &ftypes.CryptoKey{
						Size:     2048,
						Format:   ftypes.CryptoKeyFormatPKCS8,
						Encoding: ftypes.CryptoEncodingPEM,
					},
					Relationships: []ftypes.CryptoRelationship{{
						Type:         ftypes.CryptoRelationshipUsedWith,
						RelatedAsset: rsaAlgorithm.Descriptor(),
					}},
				},
				rsaAlgorithm,
			},
		},
		{
			name:  "encrypted PKCS#8 private key",
			input: fixtures.encryptedPEM,
			want: []ftypes.CryptoAssetInfo{{
				Kind:    ftypes.CryptoKindKey,
				KeyType: ftypes.CryptoKeyTypePrivate,
				// The container is identified by the DER inside the PEM block.
				Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedPKCS8SHA256, fixtures.encryptedDER),
				Name:     "Encrypted PKCS#8 private key",
				Key: &ftypes.CryptoKey{
					Format:    ftypes.CryptoKeyFormatPKCS8,
					Encoding:  ftypes.CryptoEncodingPEM,
					Encrypted: true,
				},
			}},
		},
		{
			name:  "RFC 1423 encrypted private key",
			input: fixtures.rfc1423PEM,
			want: []ftypes.CryptoAssetInfo{{
				Kind:    ftypes.CryptoKindKey,
				KeyType: ftypes.CryptoKeyTypePrivate,
				// An RFC 1423 container is identified by the whole PEM block.
				Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedRFC1423SHA256, fixtures.rfc1423PEM),
				Name:     "Encrypted PKCS#1 private key",
				Key: &ftypes.CryptoKey{
					Format:    ftypes.CryptoKeyFormatPKCS1,
					Encoding:  ftypes.CryptoEncodingPEM,
					Encrypted: true,
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parse(t, tt.input))
		})
	}
}

func TestParseCertificateName(t *testing.T) {
	fixtures := newFixtures(t)

	tests := []struct {
		name        string
		certificate *stdx509.Certificate
		want        string
	}{
		{
			name:        "common name",
			certificate: fixtures.certificate,
			want:        "example.test",
		},
		{
			name:        "distinguished name without a common name",
			certificate: fixtures.noCommonName,
			want:        "O=Example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := parse(t, certificatePEM(tt.certificate))
			assert.Equal(t, tt.want, assets[0].Name)
		})
	}
}

func TestParseCertificatePathLength(t *testing.T) {
	fixtures := newFixtures(t)

	tests := []struct {
		name           string
		certificate    *stdx509.Certificate
		wantPathLen    int
		wantPathLenSet bool
	}{
		{
			name:        "no path length",
			certificate: fixtures.certificate,
		},
		{
			name:           "explicit zero path length",
			certificate:    fixtures.pathLenZero,
			wantPathLenSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := parse(t, certificatePEM(tt.certificate))
			assert.Equal(t, tt.wantPathLen, assets[0].Certificate.MaxPathLen)
			assert.Equal(t, tt.wantPathLenSet, assets[0].Certificate.MaxPathLenZero)
		})
	}
}

// TestParseUnknownSignatureAlgorithm covers RSASSA-PSS, which the catalog leaves out
// because its variants share one OID. An algorithm outside the catalog is still described,
// named by the OID the certificate carries.
func TestParseUnknownSignatureAlgorithm(t *testing.T) {
	fixtures := newFixtures(t)

	assets := parse(t, certificatePEM(fixtures.pssCertificate))
	require.Len(t, assets, 4)

	signature := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.2.840.113549.1.1.10",
		},
		Name: "1.2.840.113549.1.1.10",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	assert.Equal(t, signature, assets[1])
	assert.Contains(t, assets[0].Relationships, ftypes.CryptoRelationship{
		Type:         ftypes.CryptoRelationshipSignedWith,
		RelatedAsset: signature.Descriptor(),
	})
}

// TestParseIdentity states what identity has to hold across files.
func TestParseIdentity(t *testing.T) {
	fixtures := newFixtures(t)

	publicKey := parse(t, fixtures.publicPEM)
	privateKey := parse(t, fixtures.pkcs8PEM)
	encryptedKey := parse(t, fixtures.encryptedPEM)
	certificate := parse(t, fixtures.certificatePEM)
	otherCertificate := parse(t, certificatePEM(fixtures.otherCertificate))

	t.Run("a private key and its public counterpart are one key of two kinds", func(t *testing.T) {
		assert.Equal(t, publicKey[0].Identity, privateKey[0].Identity)
		assert.NotEqual(t, publicKey[0].KeyType, privateKey[0].KeyType)
	})

	t.Run("an encrypted container is identified on its own", func(t *testing.T) {
		assert.NotEqual(t, publicKey[0].Identity.Method, encryptedKey[0].Identity.Method)
		assert.NotEqual(t, publicKey[0].Identity.Value, encryptedKey[0].Identity.Value)
	})

	t.Run("an encrypted container is identified by its canonical form", func(t *testing.T) {
		// The same container written with CRLF line endings and its headers in the other
		// order is one asset, because the digest is taken over the re-encoded block.
		reformatted := parse(t, []byte("-----BEGIN RSA PRIVATE KEY-----\r\n"+
			"DEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\r\n"+
			"Proc-Type: 4,ENCRYPTED\r\n\r\n"+
			"AQID\r\nBA==\r\n"+
			"-----END RSA PRIVATE KEY-----\r\n"))
		rfc1423Key := parse(t, fixtures.rfc1423PEM)
		assert.Equal(t, rfc1423Key[0].Identity, reformatted[0].Identity)
	})

	t.Run("different certificates have different identities", func(t *testing.T) {
		assert.NotEqual(t, certificate[0].Identity, otherCertificate[0].Identity)
	})

	t.Run("a certificate and a key file agree on the key they share", func(t *testing.T) {
		assert.Equal(t, publicKey[0].Identity, certificate[2].Identity)
	})
}

// parse describes a file and checks that every asset it reports is valid.
func parse(t *testing.T, content []byte) []ftypes.CryptoAssetInfo {
	t.Helper()

	assets, err := cryptox509.Parse(t.Context(), "candidate.pem", content)
	require.NoError(t, err)
	for i, asset := range assets {
		require.NoErrorf(t, asset.Validate(), "asset %d", i)
	}
	return assets
}

// recognized reduces assets to what the input was recognized as. Algorithm assets are left
// out, because a key always carries the algorithm it belongs to.
func recognized(assets []ftypes.CryptoAssetInfo) []found {
	var entries []found
	for _, asset := range assets {
		if asset.Kind == ftypes.CryptoKindAlgorithm {
			continue
		}

		entry := found{
			kind:    asset.Kind,
			keyType: asset.KeyType,
			method:  asset.Identity.Method,
		}
		switch {
		case asset.Certificate != nil:
			entry.encoding = asset.Certificate.Encoding
		case asset.Key != nil:
			entry.format = asset.Key.Format
			entry.encoding = asset.Key.Encoding
		}
		entries = append(entries, entry)
	}
	return entries
}

// testFixtures is the parsed material every test reads.
type testFixtures struct {
	certificate      *stdx509.Certificate
	pathLenZero      *stdx509.Certificate
	noCommonName     *stdx509.Certificate
	otherCertificate *stdx509.Certificate
	pssCertificate   *stdx509.Certificate
	rsaPublic        *rsa.PublicKey
	certificateDER   []byte
	certificatePEM   []byte
	pkcs1DER         []byte
	pkcs8DER         []byte
	pkcs8PEM         []byte
	sec1DER          []byte
	publicDER        []byte
	publicPEM        []byte
	encryptedDER     []byte
	encryptedPEM     []byte
	rfc1423PEM       []byte
	ed25519DER       []byte
	dsaDER           []byte
	x25519PKCS8DER   []byte
	x25519PKIXDER    []byte
	csrDER           []byte
	csrPEM           []byte
	crlDER           []byte
	crlPEM           []byte
	unsupportedDER   []byte
}

// sharedRSAKey is generated once for the package, because generating a 2048-bit key for
// every test dominates the run.
var sharedRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func newFixtures(t *testing.T) testFixtures {
	t.Helper()

	rsaKey := sharedRSAKey()
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	workload, err := url.Parse("spiffe://example.test/workload")
	require.NoError(t, err)

	// A certificate carrying every field a description reads. It signs the revocation list
	// below as well, which is what its cRLSign usage and subject key identifier are for.
	certificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(0x123456789),
		Subject:      pkix.Name{CommonName: "example.test"},
		SubjectKeyId: []byte{0x01, 0x02, 0x03},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
		KeyUsage: stdx509.KeyUsageDigitalSignature |
			stdx509.KeyUsageKeyEncipherment |
			stdx509.KeyUsageCertSign |
			stdx509.KeyUsageCRLSign,
		ExtKeyUsage: []stdx509.ExtKeyUsage{
			stdx509.ExtKeyUsageServerAuth,
			stdx509.ExtKeyUsageClientAuth,
		},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}},
		DNSNames:           []string{"example.test", "www.example.test"},
		EmailAddresses:     []string{"admin@example.test"},
		IPAddresses:        []net.IP{net.ParseIP("192.0.2.1")},
		URIs:               []*url.URL{workload},
		// Basic constraints without a path length, which crypto/x509 parses back as -1.
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, rsaKey)

	pathLenZero := newCertificate(t, &stdx509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "leaf.example.test"},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}, rsaKey)

	noCommonName := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{Organization: []string{"Example"}},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}, rsaKey)

	otherCertificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "other.test"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}, rsaKey)

	// A certificate signed with RSASSA-PSS, whose OID the catalog leaves out.
	pssCertificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber:       big.NewInt(5),
		Subject:            pkix.Name{CommonName: "pss.example.test"},
		NotBefore:          time.Unix(1, 0),
		NotAfter:           time.Unix(2, 0),
		SignatureAlgorithm: stdx509.SHA256WithRSAPSS,
	}, rsaKey)

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
	_, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed25519DER, err := stdx509.MarshalPKCS8PrivateKey(ed25519Private)
	require.NoError(t, err)
	// crypto/x509 parses a DSA key but cannot encode one, so the input comes from pkg/crypto.
	dsaDER, err := crypto.MarshalPublicKey(&dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: big.NewInt(23),
			Q: big.NewInt(11),
			G: big.NewInt(2),
		},
		Y: big.NewInt(4),
	})
	require.NoError(t, err)

	// Encrypted containers, kept opaque because the parser only validates the envelope.
	encryptedDER, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2},
		EncryptedData: []byte{0x01, 0x02, 0x03},
	})
	require.NoError(t, err)
	rfc1423PEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC,00112233445566778899AABBCCDDEEFF",
		},
		Bytes: []byte{0x01, 0x02, 0x03, 0x04},
	})

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

	return testFixtures{
		certificate:      certificate,
		pathLenZero:      pathLenZero,
		noCommonName:     noCommonName,
		otherCertificate: otherCertificate,
		pssCertificate:   pssCertificate,
		rsaPublic:        &rsaKey.PublicKey,
		certificateDER:   certificate.Raw,
		certificatePEM:   certificatePEM(certificate),
		pkcs1DER:         stdx509.MarshalPKCS1PrivateKey(rsaKey),
		pkcs8DER:         pkcs8DER,
		pkcs8PEM:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
		sec1DER:          sec1DER,
		publicDER:        publicDER,
		publicPEM:        pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		encryptedDER:     encryptedDER,
		encryptedPEM:     pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER}),
		rfc1423PEM:       rfc1423PEM,
		ed25519DER:       ed25519DER,
		dsaDER:           dsaDER,
		x25519PKCS8DER:   x25519PKCS8DER,
		x25519PKIXDER:    x25519PKIXDER,
		csrDER:           csrDER,
		csrPEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		crlDER:           crlDER,
		crlPEM:           pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}),
		unsupportedDER:   unsupportedDER,
	}
}

// newCertificate self-signs a template and parses it back, because a template alone has
// no raw DER to identify and no parsed basic constraints.
func newCertificate(t *testing.T, template *stdx509.Certificate, key *rsa.PrivateKey) *stdx509.Certificate {
	t.Helper()

	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := stdx509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func certificatePEM(certificate *stdx509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
}

// spkiIdentity is the identity of a key, taken over its PKIX SubjectPublicKeyInfo.
func spkiIdentity(t *testing.T, pub any) ftypes.CryptoIdentity {
	t.Helper()

	der, err := stdx509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	return ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, der)
}
