package crypto_test

import (
	"crypto/dsa"
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
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	cryptox509 "github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type extractorFixtures struct {
	certificate      *stdx509.Certificate
	pathLenZero      *stdx509.Certificate
	noCommonName     *stdx509.Certificate
	otherCertificate *stdx509.Certificate
	pssCertificate   *stdx509.Certificate
	rsaPublic        *rsa.PublicKey
	ecdsaPublic      *ecdsa.PublicKey
	ed25519Public    ed25519.PublicKey
	dsaPublic        *dsa.PublicKey
	encryptedDigest  string
}

func TestExtract(t *testing.T) {
	fixtures := newExtractorFixtures(t)
	certificateDigest := sha256.Sum256(fixtures.certificate.Raw)

	// The algorithm of an RSA key cannot be told apart from a signature algorithm by its
	// OID alone, so it carries an unknown primitive and no family.
	rsaAlgorithm := ftypes.CryptoAsset{
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
	ecAlgorithm := ftypes.CryptoAsset{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.10045.2.1",
			Parameters: "curve=P-256",
		},
		Name: "EC-P-256",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	ed25519Algorithm := ftypes.CryptoAsset{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.3.101.112",
		},
		Name: "Ed25519",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "EdDSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	dsaAlgorithm := ftypes.CryptoAsset{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.10040.4.1",
			Parameters: "key-size=2048",
		},
		Name: "DSA-2048",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "DSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	signatureAlgorithm := ftypes.CryptoAsset{
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
	certificateKey := ftypes.CryptoAsset{
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
		name   string
		object cryptox509.Object
		want   []ftypes.CryptoAsset
	}{
		{
			name: "certificate",
			object: cryptox509.Object{
				Kind:        cryptox509.ObjectCertificate,
				Certificate: fixtures.certificate,
				Encoding:    ftypes.CryptoEncodingPEM,
			},
			want: []ftypes.CryptoAsset{
				{
					Kind: ftypes.CryptoKindCertificate,
					Identity: ftypes.CryptoIdentity{
						Method: ftypes.CryptoMethodSHA256,
						Value:  hex.EncodeToString(certificateDigest[:]),
					},
					Name: "example.test",
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
			name: "RSA public key",
			object: cryptox509.Object{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  ftypes.CryptoEncodingPEM,
				KeyFormat: ftypes.CryptoKeyFormatPKIX,
			},
			want: []ftypes.CryptoAsset{
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
			name: "ECDSA public key",
			object: cryptox509.Object{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.ecdsaPublic,
				Encoding:  ftypes.CryptoEncodingDER,
				KeyFormat: ftypes.CryptoKeyFormatPKIX,
			},
			want: []ftypes.CryptoAsset{
				{
					Kind:     ftypes.CryptoKindKey,
					KeyType:  ftypes.CryptoKeyTypePublic,
					Identity: spkiIdentity(t, fixtures.ecdsaPublic),
					Name:     "EC-P-256 public key",
					Key: &ftypes.CryptoKey{
						Size:     256,
						Curve:    "P-256",
						Format:   ftypes.CryptoKeyFormatPKIX,
						Encoding: ftypes.CryptoEncodingDER,
					},
					Relationships: []ftypes.CryptoRelationship{{
						Type:         ftypes.CryptoRelationshipUsedWith,
						RelatedAsset: ecAlgorithm.Descriptor(),
					}},
				},
				ecAlgorithm,
			},
		},
		{
			name: "Ed25519 public key",
			object: cryptox509.Object{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.ed25519Public,
				Encoding:  ftypes.CryptoEncodingPEM,
				KeyFormat: ftypes.CryptoKeyFormatPKIX,
			},
			want: []ftypes.CryptoAsset{
				{
					Kind:     ftypes.CryptoKindKey,
					KeyType:  ftypes.CryptoKeyTypePublic,
					Identity: spkiIdentity(t, fixtures.ed25519Public),
					Name:     "Ed25519 public key",
					Key: &ftypes.CryptoKey{
						Size:     256,
						Format:   ftypes.CryptoKeyFormatPKIX,
						Encoding: ftypes.CryptoEncodingPEM,
					},
					Relationships: []ftypes.CryptoRelationship{{
						Type:         ftypes.CryptoRelationshipUsedWith,
						RelatedAsset: ed25519Algorithm.Descriptor(),
					}},
				},
				ed25519Algorithm,
			},
		},
		{
			// The parser projects a private key to its public part, so only the key type differs.
			name: "private key",
			object: cryptox509.Object{
				Kind:      cryptox509.ObjectPrivateKey,
				PublicKey: fixtures.rsaPublic,
				Encoding:  ftypes.CryptoEncodingPEM,
				KeyFormat: ftypes.CryptoKeyFormatPKCS8,
			},
			want: []ftypes.CryptoAsset{
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
			name: "encrypted private key",
			object: cryptox509.Object{
				Kind:                 cryptox509.ObjectEncryptedPrivateKey,
				EncryptedPKCS8SHA256: fixtures.encryptedDigest,
				Encoding:             ftypes.CryptoEncodingPEM,
				KeyFormat:            ftypes.CryptoKeyFormatPKCS8,
			},
			want: []ftypes.CryptoAsset{{
				Kind:    ftypes.CryptoKindKey,
				KeyType: ftypes.CryptoKeyTypePrivate,
				Identity: ftypes.CryptoIdentity{
					Method: ftypes.CryptoMethodEncryptedPKCS8SHA256,
					Value:  fixtures.encryptedDigest,
				},
				Name: "Encrypted PKCS#8 private key",
				Key: &ftypes.CryptoKey{
					Format:    ftypes.CryptoKeyFormatPKCS8,
					Encoding:  ftypes.CryptoEncodingPEM,
					Encrypted: true,
				},
			}},
		},
		{
			name: "DSA public key",
			object: cryptox509.Object{
				Kind:      cryptox509.ObjectPublicKey,
				PublicKey: fixtures.dsaPublic,
				Encoding:  ftypes.CryptoEncodingDER,
				KeyFormat: ftypes.CryptoKeyFormatPKIX,
			},
			want: []ftypes.CryptoAsset{
				{
					Kind:     ftypes.CryptoKindKey,
					KeyType:  ftypes.CryptoKeyTypePublic,
					Identity: spkiIdentity(t, fixtures.dsaPublic),
					Name:     "DSA-2048 public key",
					Key: &ftypes.CryptoKey{
						Size:     2048,
						Format:   ftypes.CryptoKeyFormatPKIX,
						Encoding: ftypes.CryptoEncodingDER,
					},
					Relationships: []ftypes.CryptoRelationship{{
						Type:         ftypes.CryptoRelationshipUsedWith,
						RelatedAsset: dsaAlgorithm.Descriptor(),
					}},
				},
				dsaAlgorithm,
			},
		},
		{
			// A key that cannot be canonicalized has no identity, so nothing is reported
			// for it, not even the algorithm it would belong to.
			name:   "key with no canonical form",
			object: cryptox509.Object{Kind: cryptox509.ObjectPublicKey},
		},
		{
			name:   "unknown object kind",
			object: cryptox509.Object{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := crypto.Extract(tt.object)
			assert.Equal(t, tt.want, got)

			for i, asset := range got {
				require.NoErrorf(t, asset.Validate(), "asset %d", i)
			}
		})
	}
}

func TestExtractCertificateName(t *testing.T) {
	fixtures := newExtractorFixtures(t)

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
			assets := crypto.Extract(cryptox509.Object{
				Kind:        cryptox509.ObjectCertificate,
				Certificate: tt.certificate,
			})
			require.NotEmpty(t, assets)
			assert.Equal(t, tt.want, assets[0].Name)
		})
	}
}

func TestExtractCertificatePathLength(t *testing.T) {
	fixtures := newExtractorFixtures(t)

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
			assets := crypto.Extract(cryptox509.Object{
				Kind:        cryptox509.ObjectCertificate,
				Certificate: tt.certificate,
			})
			require.NotEmpty(t, assets)
			assert.Equal(t, tt.wantPathLen, assets[0].Certificate.MaxPathLen)
			assert.Equal(t, tt.wantPathLenSet, assets[0].Certificate.MaxPathLenZero)
		})
	}
}

// TestExtractUnknownSignatureAlgorithm covers RSASSA-PSS, which the catalog leaves out
// because its variants share one OID. An algorithm outside the catalog is still described,
// named by the OID the certificate carries, and the certificate keeps its signature
// relationship.
func TestExtractUnknownSignatureAlgorithm(t *testing.T) {
	fixtures := newExtractorFixtures(t)

	assets := crypto.Extract(cryptox509.Object{
		Kind:        cryptox509.ObjectCertificate,
		Certificate: fixtures.pssCertificate,
	})
	require.Len(t, assets, 4)

	signature := ftypes.CryptoAsset{
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

	for i, asset := range assets {
		require.NoErrorf(t, asset.Validate(), "asset %d", i)
	}
}

func TestExtractIdentity(t *testing.T) {
	fixtures := newExtractorFixtures(t)

	publicKey := crypto.Extract(cryptox509.Object{
		Kind:      cryptox509.ObjectPublicKey,
		PublicKey: fixtures.rsaPublic,
		KeyFormat: ftypes.CryptoKeyFormatPKIX,
	})
	privateKey := crypto.Extract(cryptox509.Object{
		Kind:      cryptox509.ObjectPrivateKey,
		PublicKey: fixtures.rsaPublic,
		KeyFormat: ftypes.CryptoKeyFormatPKCS8,
	})
	encryptedKey := crypto.Extract(cryptox509.Object{
		Kind:                 cryptox509.ObjectEncryptedPrivateKey,
		EncryptedPKCS8SHA256: fixtures.encryptedDigest,
		KeyFormat:            ftypes.CryptoKeyFormatPKCS8,
	})
	certificate := crypto.Extract(cryptox509.Object{
		Kind:        cryptox509.ObjectCertificate,
		Certificate: fixtures.certificate,
	})
	otherCertificate := crypto.Extract(cryptox509.Object{
		Kind:        cryptox509.ObjectCertificate,
		Certificate: fixtures.otherCertificate,
	})
	require.NotEmpty(t, publicKey)
	require.NotEmpty(t, privateKey)
	require.NotEmpty(t, encryptedKey)
	require.NotEmpty(t, certificate)
	require.NotEmpty(t, otherCertificate)

	t.Run("a private key and its public counterpart share an identity", func(t *testing.T) {
		assert.Equal(t, publicKey[0].Identity, privateKey[0].Identity)
		assert.NotEqual(t, publicKey[0].Descriptor(), privateKey[0].Descriptor())
	})

	t.Run("an encrypted container is identified on its own", func(t *testing.T) {
		assert.NotEqual(t, privateKey[0].Identity.Method, encryptedKey[0].Identity.Method)
		assert.NotEqual(t, privateKey[0].Identity.Value, encryptedKey[0].Identity.Value)
	})

	t.Run("different certificates have different identities", func(t *testing.T) {
		assert.NotEqual(t, certificate[0].Identity, otherCertificate[0].Identity)
	})

	t.Run("a certificate and a key file agree on the key they share", func(t *testing.T) {
		// The certificate carries the key the fixtures also expose on its own, so both
		// paths have to canonicalize it into the same identity.
		assert.Equal(t, publicKey[0].Identity, certificate[2].Identity)
	})
}

// TestMarshalDSAPublicKey checks the encoding against crypto/x509, which parses this form
// even though it cannot produce it. Every other key type is encoded by crypto/x509 itself.
func TestMarshalDSAPublicKey(t *testing.T) {
	fixtures := newExtractorFixtures(t)

	der, err := crypto.MarshalPublicKey(fixtures.dsaPublic)
	require.NoError(t, err)

	parsed, err := stdx509.ParsePKIXPublicKey(der)
	require.NoError(t, err)
	assert.Equal(t, fixtures.dsaPublic, parsed)
}

func newExtractorFixtures(t *testing.T) extractorFixtures {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ed25519Public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	workload, err := url.Parse("spiffe://example.test/workload")
	require.NoError(t, err)

	// A certificate carrying every field the extractor reads.
	certificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(0x123456789),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
		KeyUsage: stdx509.KeyUsageDigitalSignature |
			stdx509.KeyUsageKeyEncipherment |
			stdx509.KeyUsageCertSign,
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

	digest := sha256.Sum256([]byte("encrypted PKCS#8 container"))

	return extractorFixtures{
		certificate:      certificate,
		pathLenZero:      pathLenZero,
		noCommonName:     noCommonName,
		otherCertificate: otherCertificate,
		pssCertificate:   pssCertificate,
		rsaPublic:        &rsaKey.PublicKey,
		ecdsaPublic:      &ecdsaKey.PublicKey,
		ed25519Public:    ed25519Public,
		dsaPublic: &dsa.PublicKey{
			Parameters: dsa.Parameters{
				// A 2048-bit modulus, so that the reported key size is a realistic one.
				// The group is not a valid one, which nothing on this path checks.
				P: new(big.Int).Lsh(big.NewInt(1), 2047),
				Q: big.NewInt(11),
				G: big.NewInt(2),
			},
			Y: big.NewInt(4),
		},
		encryptedDigest: hex.EncodeToString(digest[:]),
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

func spkiIdentity(t *testing.T, pub any) ftypes.CryptoIdentity {
	t.Helper()

	der, err := crypto.MarshalPublicKey(pub)
	require.NoError(t, err)

	digest := sha256.Sum256(der)
	return ftypes.CryptoIdentity{
		Method: ftypes.CryptoMethodSPKISHA256,
		Value:  hex.EncodeToString(digest[:]),
	}
}
