package x509_test

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
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

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	cryptox509 "github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

var oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

// parsedFilePath is the path every fixture is parsed from.
const parsedFilePath = "candidate.pem"

// ed448CertificatePEM is a self-signed Ed448 certificate. crypto/x509 cannot produce Ed448,
// so the certificate comes from OpenSSL:
//
//	docker run --rm alpine:3.22 sh -c '
//	  apk add -q openssl &&
//	  openssl req -x509 -newkey ed448 -nodes -keyout /dev/null -subj /CN=ed448 -days 36500'
const ed448CertificatePEM = `-----BEGIN CERTIFICATE-----
MIIBgjCCAQKgAwIBAgIUXjC0zfeRr1tKlPH01JudKhbbujIwBQYDK2VxMBAxDjAM
BgNVBAMMBWVkNDQ4MCAXDTI2MDkzMDE5MjEzNloYDzIxMjYwOTA2MTkyMTM2WjAQ
MQ4wDAYDVQQDDAVlZDQ0ODBDMAUGAytlcQM6AEe7Olbxb3pqiF3ZlFpZSzKCuIVf
TGaVwjNrlpmwIfujqX+dS68NgAi8zDuCt/V22LHVpb75i+eJgKNTMFEwHQYDVR0O
BBYEFEQQUJqc4ai0yXXJ6yg2HcqZ93xhMB8GA1UdIwQYMBaAFEQQUJqc4ai0yXXJ
6yg2HcqZ93xhMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VxA3MAapmNjvh52MQOqubx
gOyTIZvn/PYk1GLkbo/vwuOLzlhXbwgPri/+/REAaEgDT1z2sFFWZtW4uEiAOk7c
dhs/7xE1qADrTOKPdVDihzknrv7b6ArpxALMVANmMQs60UJiq+olpP3E1ik3G93W
Vx7bhgEA
-----END CERTIFICATE-----
`

// x448CertificatePEM is a certificate for an X448 key, signed with an Ed25519 key. Neither
// crypto/x509 nor the catalog knows X448, and the certificate comes from OpenSSL:
//
//	docker run --rm alpine:3.22 sh -c '
//	  apk add -q openssl &&
//	  openssl genpkey -algorithm ed25519 -out ca.key &&
//	  openssl genpkey -algorithm x448 | openssl pkey -pubout -out x448.pub &&
//	  openssl x509 -new -subj /CN=x448 -key ca.key -force_pubkey x448.pub -days 36500'
const x448CertificatePEM = `-----BEGIN CERTIFICATE-----
MIIBOzCB7qADAgECAhQ/ypyR9JPJ51E6Zo3JMU+k9OPRTTAFBgMrZXAwDzENMAsG
A1UEAwwEeDQ0ODAgFw0yNjA5MzAxOTIxNDdaGA8yMTI2MDkwNjE5MjE0N1owDzEN
MAsGA1UEAwwEeDQ0ODBCMAUGAytlbwM5AI2vRDNDpFDXbWHWQZSQJZMC68HycEje
lUmdofOaX2Vmm5Z+vvckw36hNbzgxHjZE6Q2IpVTLLTFo0IwQDAdBgNVHQ4EFgQU
xVYou1Zp7144roqlk6PLLOrFCtIwHwYDVR0jBBgwFoAUbsD0cKe8eRJGavxI6a4B
HdMHSQcwBQYDK2VwA0EAevJaAE+dQj+/CvhmsSNqV89aQK0Mj71LvZb8s6dqbf6h
7SDrhK1yzj+q7xsK80PFrz22kr4z4iyPkpQzscaeAQ==
-----END CERTIFICATE-----
`

// x25519CertificatePEM is a certificate for an X25519 key, signed with an Ed25519 key.
// crypto/x509 cannot produce a certificate for an X25519 key, so the certificate comes
// from OpenSSL:
//
//	docker run --rm alpine:3.22 sh -c '
//	  apk add -q openssl &&
//	  openssl genpkey -algorithm ed25519 -out ca.key &&
//	  openssl genpkey -algorithm x25519 | openssl pkey -pubout -out x25519.pub &&
//	  openssl x509 -new -subj /CN=x25519 -key ca.key -force_pubkey x25519.pub -days 36500'
const x25519CertificatePEM = `-----BEGIN CERTIFICATE-----
MIIBJzCB2qADAgECAhRp4xwAGFhPCNyRBzBnMeNKJ5pNizAFBgMrZXAwETEPMA0G
A1UEAwwGeDI1NTE5MCAXDTI2MTAxNjA3MDAyMVoYDzIxMjYwOTIyMDcwMDIxWjAR
MQ8wDQYDVQQDDAZ4MjU1MTkwKjAFBgMrZW4DIQChIW9VV7z3EShsVfSFuyOV4niP
qOzHvxYcFP5vLpA0BaNCMEAwHQYDVR0OBBYEFID6WaVHKSI0rkZHUOWSCos8bkhZ
MB8GA1UdIwQYMBaAFPfrO0E6WViyVa41wZYGMDQSuVGsMAUGAytlcANBAA6Ng4IP
wPyCQoe49bPiUWB8/x06gL27PLIqu2ZglEe/VC6SRV+0yHcrlalqxtq7s67IbH2k
73n1umdEMGmbiw8=
-----END CERTIFICATE-----
`

// The P-192 fixtures are a self-signed certificate and its key in every form the parser
// reads. crypto/x509 does not support P-192, so they come from OpenSSL:
//
//	docker run --rm alpine:3.22 sh -c '
//	  apk add -q openssl &&
//	  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-192 -nodes -keyout key.pem -subj /CN=p192 -days 36500 &&
//	  cat key.pem &&
//	  openssl ec -in key.pem &&
//	  openssl pkey -in key.pem -pubout'
const (
	p192CertificatePEM = `-----BEGIN CERTIFICATE-----
MIIBVTCCAQugAwIBAgIUYOyOWGD1O9UuPc8l8IFxG8v67NEwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEcDE5MjAgFw0yNjEwMTYxMjQ5MTNaGA8yMTI2MDkyMjEyNDkx
M1owDzENMAsGA1UEAwwEcDE5MjBJMBMGByqGSM49AgEGCCqGSM49AwEBAzIABBYq
XHGsm8w7kRzKfRouJTjxdzufi3eLlJChrD0hWN8VQkeSZqmnFSTPxLLDWbnGN6NT
MFEwHQYDVR0OBBYEFPjzRjRj0sLkKoupN9gJiDZ1CLFbMB8GA1UdIwQYMBaAFPjz
RjRj0sLkKoupN9gJiDZ1CLFbMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID
OAAwNQIZAO/H03Gm8vN/34wxNd0vju0uSM+Shr7SzgIYIVZ+alM5dclVBAXpBhJX
GKh8LkK0kF4z
-----END CERTIFICATE-----
`
	p192PKCS8PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MG8CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEVTBTAgEBBBgQW7hyOKagpDHl65RX
R+R18SRA2nYcse6hNAMyAAQWKlxxrJvMO5Ecyn0aLiU48Xc7n4t3i5SQoaw9IVjf
FUJHkmappxUkz8Syw1m5xjc=
-----END PRIVATE KEY-----
`
	p192SEC1PrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MF8CAQEEGBBbuHI4pqCkMeXrlFdH5HXxJEDadhyx7qAKBggqhkjOPQMBAaE0AzIA
BBYqXHGsm8w7kRzKfRouJTjxdzufi3eLlJChrD0hWN8VQkeSZqmnFSTPxLLDWbnG
Nw==
-----END EC PRIVATE KEY-----
`
	p192PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEFipccaybzDuRHMp9Gi4lOPF3O5+L
d4uUkKGsPSFY3xVCR5JmqacVJM/EssNZucY3
-----END PUBLIC KEY-----
`
)

// rsaPrivateKeyDER encodes a structurally valid 2048-bit RSA key in PKCS#1 after applying
// mutate to it. Its values are not consistent with each other.
func rsaPrivateKeyDER(t *testing.T, mutate func(*cryptox509.PKCS1PrivateKey)) []byte {
	t.Helper()
	one := big.NewInt(1)
	key := cryptox509.PKCS1PrivateKey{
		N:    new(big.Int).Lsh(one, 2047),
		E:    65537,
		D:    one,
		P:    one,
		Q:    one,
		Dp:   one,
		Dq:   one,
		Qinv: one,
	}
	mutate(&key)
	der, err := asn1.Marshal(key)
	require.NoError(t, err)
	return der
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
	// P is longer than the modulus.
	invalidRSAKey := rsaPrivateKeyDER(t, func(k *cryptox509.PKCS1PrivateKey) {
		k.P = new(big.Int).Lsh(big.NewInt(1), 24575)
	})
	// crypto/x509 reads a key that omits its CRT values.
	rsaKeyWithoutCRT := rsaPrivateKeyDER(t, func(k *cryptox509.PKCS1PrivateKey) {
		k.Dp, k.Dq, k.Qinv = nil, nil, nil
	})
	rsaKeyWithZeroPrime := rsaPrivateKeyDER(t, func(k *cryptox509.PKCS1PrivateKey) {
		k.Version = 1
		k.AdditionalPrimes = []cryptox509.PKCS1AdditionalPrime{{Prime: big.NewInt(0), Exp: big.NewInt(1), Coeff: big.NewInt(1)}}
	})
	invalidRSAKeyPKCS8, err := asn1.Marshal(cryptox509.PKCS8PrivateKey{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  cryptox509.OIDRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		PrivateKey: invalidRSAKey,
	})
	require.NoError(t, err)

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
	pemPublicKey := found{
		kind:     ftypes.CryptoKindKey,
		keyType:  ftypes.CryptoKeyTypePublic,
		method:   ftypes.CryptoMethodSPKISHA256,
		format:   ftypes.CryptoKeyFormatPKIX,
		encoding: ftypes.CryptoEncodingPEM,
	}
	pemPKCS1PrivateKey := found{
		kind:     ftypes.CryptoKindKey,
		keyType:  ftypes.CryptoKeyTypePrivate,
		method:   ftypes.CryptoMethodSPKISHA256,
		format:   ftypes.CryptoKeyFormatPKCS1,
		encoding: ftypes.CryptoEncodingPEM,
	}
	pemPKCS8PrivateKey := found{
		kind:     ftypes.CryptoKindKey,
		keyType:  ftypes.CryptoKeyTypePrivate,
		method:   ftypes.CryptoMethodSPKISHA256,
		format:   ftypes.CryptoKeyFormatPKCS8,
		encoding: ftypes.CryptoEncodingPEM,
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
			want:  []found{pemPKCS8PrivateKey},
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
			want:  []found{pemPublicKey},
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
			name:  "ML-DSA PKCS8 DER",
			input: fixtures.mldsaDER,
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
			name:  "repeated certificate",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.certificatePEM}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
			},
		},
		{
			// Both certificates carry the same key.
			name:  "certificate bundle",
			input: bytes.Join([][]byte{fixtures.certificatePEM, certificatePEM(fixtures.otherCertificate)}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
				pemCertificate,
			},
		},
		{
			name:  "certificate bundle with a malformed key",
			input: bytes.Join([][]byte{fixtures.certificatePEM, certificatePEM(fixtures.malformedKeyCertificate)}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
			},
		},
		{
			name:  "X25519 certificate PEM",
			input: certificatePEM(fixtures.x25519Certificate),
			want: []found{
				pemCertificate,
				certificateKey,
			},
		},
		{
			// The key is found twice, because the certificate gives it no container.
			name:  "certificate and its public key",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.publicPEM}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
				pemPublicKey,
			},
		},
		{
			name:  "certificate and private key",
			input: bytes.Join([][]byte{fixtures.certificatePEM, fixtures.pkcs8PEM}, nil),
			want: []found{
				pemCertificate,
				certificateKey,
				pemPKCS8PrivateKey,
			},
		},
		{
			name: "same key in two containers",
			input: bytes.Join([][]byte{
				pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: fixtures.pkcs1DER}),
				fixtures.pkcs8PEM,
			}, nil),
			want: []found{
				pemPKCS1PrivateKey,
				pemPKCS8PrivateKey,
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
			name:  "invalid RSA key PKCS1 PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: invalidRSAKey}),
			want:  []found{pemPKCS1PrivateKey},
		},
		{
			name:  "invalid RSA key PKCS8 PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: invalidRSAKeyPKCS8}),
			want:  []found{pemPKCS8PrivateKey},
		},
		{
			name:  "RSA key without CRT values PKCS1 PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaKeyWithoutCRT}),
			want:  []found{pemPKCS1PrivateKey},
		},
		{
			name:  "RSA key with zero additional prime PKCS1 PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaKeyWithZeroPrime}),
		},
		{
			name:  "invalid RSA key PKCS1 DER",
			input: invalidRSAKey,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePrivate,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKCS1,
				encoding: ftypes.CryptoEncodingDER,
			}},
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
			name:  "X25519 PKIX public PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixtures.x25519PKIXDER}),
			want:  []found{pemPublicKey},
		},
		{
			name:  "X25519 PKIX public DER",
			input: fixtures.x25519PKIXDER,
			want: []found{{
				kind:     ftypes.CryptoKindKey,
				keyType:  ftypes.CryptoKeyTypePublic,
				method:   ftypes.CryptoMethodSPKISHA256,
				format:   ftypes.CryptoKeyFormatPKIX,
				encoding: ftypes.CryptoEncodingDER,
			}},
		},
		{
			name:  "Ed448 PKIX public PEM",
			input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixtures.ed448Certificate.RawSubjectPublicKeyInfo}),
			want:  []found{pemPublicKey},
		},
		{
			name:  "malformed Ed25519 key under PUBLIC KEY",
			input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixtures.malformedEd25519PKIXDER}),
		},
		{
			name:  "malformed X25519 key under PUBLIC KEY",
			input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixtures.malformedX25519PKIXDER}),
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

	ecAlgorithm := ftypes.CryptoAssetInfo{
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
	p192Algorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.10045.2.1",
			Parameters: "curve=P-192",
		},
		Name: "EC-P-192",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	var p192Certificate struct {
		TBSCertificate asn1.RawValue
	}
	_, err := asn1.Unmarshal(decodePEM(t, p192CertificatePEM), &p192Certificate)
	require.NoError(t, err)
	p192UnsignedCertificate, err := asn1.Marshal(p192Certificate)
	require.NoError(t, err)
	ecSignatureAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.2.840.10045.4.3.2",
		},
		Name: "ECDSA-SHA-256",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "ECDSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	ecCertificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: spkiIdentity(t, fixtures.ecdsaCertificate.PublicKey),
		Name:     "EC-P-256 public key",
		Key: &ftypes.CryptoKey{
			Size:  256,
			Curve: "P-256",
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: ecAlgorithm.Descriptor(),
		}},
	}

	// Ed25519 fixes its parameters through the curve, so the algorithm carries none.
	ed25519Algorithm := ftypes.CryptoAssetInfo{
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
	ed25519CertificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: spkiIdentity(t, fixtures.ed25519Certificate.PublicKey),
		Name:     "Ed25519 public key",
		Key: &ftypes.CryptoKey{
			Size: 256,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: ed25519Algorithm.Descriptor(),
		}},
	}

	mldsaAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "2.16.840.1.101.3.4.3.18",
		},
		Name: "ML-DSA-65",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "ML-DSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	mldsaCertificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: spkiIdentity(t, fixtures.mldsaCertificate.PublicKey),
		Name:     "ML-DSA-65 public key",
		Key: &ftypes.CryptoKey{
			Size: 1952 * 8,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: mldsaAlgorithm.Descriptor(),
		}},
	}

	// DSA keys of one L can differ in N, so both identify the algorithm.
	dsaAlgorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      "1.2.840.10040.4.1",
			Parameters: "key-size=2048,subgroup-size=224",
		},
		Name: "DSA-2048",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "DSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}

	// crypto/x509 does not parse an Ed448 key, so the key is described from its encoded
	// form, and its size comes from the OID.
	ed448Algorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.3.101.113",
		},
		Name: "Ed448",
		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    "EdDSA",
			Primitive: ftypes.CryptoPrimitiveSignature,
		},
	}
	ed448CertificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, fixtures.ed448Certificate.RawSubjectPublicKeyInfo),
		Name:     "Ed448 public key",
		Key: &ftypes.CryptoKey{
			Size: 456,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: ed448Algorithm.Descriptor(),
		}},
	}

	x448Algorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.3.101.111",
		},
		Name: "1.3.101.111",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	x448CertificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, fixtures.x448Certificate.RawSubjectPublicKeyInfo),
		Name:     "1.3.101.111 public key",
		Key: &ftypes.CryptoKey{
			Size: 448,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: x448Algorithm.Descriptor(),
		}},
	}

	x25519Algorithm := ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodOID,
			Value:  "1.3.101.110",
		},
		Name: "1.3.101.110",
		Algorithm: &ftypes.CryptoAlgorithm{
			Primitive: ftypes.CryptoPrimitiveUnknown,
		},
	}
	x25519CertificateKey := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePublic,
		Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, fixtures.x25519Certificate.RawSubjectPublicKeyInfo),
		Name:     "1.3.101.110 public key",
		Key: &ftypes.CryptoKey{
			Size: 256,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: x25519Algorithm.Descriptor(),
		}},
	}

	// at states where a description was found.
	at := func(info ftypes.CryptoAssetInfo) ftypes.CryptoAsset {
		return ftypes.CryptoAsset{
			CryptoAssetInfo: info,
			FilePath:        parsedFilePath,
		}
	}

	tests := []struct {
		name  string
		input []byte
		want  []ftypes.CryptoAsset
	}{
		{
			name:  "certificate",
			input: fixtures.certificatePEM,
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
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
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(signatureAlgorithm),
				at(certificateKey),
				at(rsaAlgorithm),
			},
		},
		{
			// The key algorithm takes its parameter from the key the certificate carries.
			name:  "EC certificate",
			input: certificatePEM(fixtures.ecdsaCertificate),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindCertificate,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.ecdsaCertificate.Raw),
						Name:     "ec.example.test",
						Certificate: &ftypes.CryptoCertificate{
							Subject:      "CN=ec.example.test",
							Issuer:       "CN=ec.example.test",
							SerialNumber: "6",
							NotBefore:    time.Unix(1, 0).UTC(),
							NotAfter:     time.Unix(2, 0).UTC(),
							Format:       ftypes.CryptoCertificateFormatX509,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: ecSignatureAlgorithm.Descriptor(),
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: ecCertificateKey.Descriptor(),
							},
						},
					},
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(ecSignatureAlgorithm),
				at(ecCertificateKey),
				at(ecAlgorithm),
			},
		},
		{
			// One OID describes the signature and the key, so the algorithm is reported once.
			name:  "Ed25519 certificate",
			input: certificatePEM(fixtures.ed25519Certificate),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindCertificate,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.ed25519Certificate.Raw),
						Name:     "ed25519.example.test",
						Certificate: &ftypes.CryptoCertificate{
							Subject:      "CN=ed25519.example.test",
							Issuer:       "CN=ed25519.example.test",
							SerialNumber: "7",
							NotBefore:    time.Unix(1, 0).UTC(),
							NotAfter:     time.Unix(2, 0).UTC(),
							Format:       ftypes.CryptoCertificateFormatX509,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: ed25519Algorithm.Descriptor(),
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: ed25519CertificateKey.Descriptor(),
							},
						},
					},
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(ed25519Algorithm),
				at(ed25519CertificateKey),
			},
		},
		{
			name:  "ML-DSA certificate",
			input: certificatePEM(fixtures.mldsaCertificate),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindCertificate,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.mldsaCertificate.Raw),
						Name:     "mldsa.example.test",
						Certificate: &ftypes.CryptoCertificate{
							Subject:      "CN=mldsa.example.test",
							Issuer:       "CN=mldsa.example.test",
							SerialNumber: "8",
							NotBefore:    time.Unix(1, 0).UTC(),
							NotAfter:     time.Unix(2, 0).UTC(),
							Format:       ftypes.CryptoCertificateFormatX509,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: mldsaAlgorithm.Descriptor(),
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: mldsaCertificateKey.Descriptor(),
							},
						},
					},
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(mldsaAlgorithm),
				at(mldsaCertificateKey),
			},
		},
		{
			name:  "Ed448 certificate",
			input: []byte(ed448CertificatePEM),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindCertificate,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.ed448Certificate.Raw),
						Name:     "ed448",
						Certificate: &ftypes.CryptoCertificate{
							Subject:               "CN=ed448",
							Issuer:                "CN=ed448",
							SerialNumber:          "5e30b4cdf791af5b4a94f1f4d49b9d2a16dbba32",
							NotBefore:             time.Date(2026, time.September, 30, 19, 21, 36, 0, time.UTC),
							NotAfter:              time.Date(2126, time.September, 6, 19, 21, 36, 0, time.UTC),
							Format:                ftypes.CryptoCertificateFormatX509,
							BasicConstraintsValid: true,
							IsCA:                  true,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: ed448Algorithm.Descriptor(),
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: ed448CertificateKey.Descriptor(),
							},
						},
					},
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(ed448Algorithm),
				at(ed448CertificateKey),
			},
		},
		{
			// A key algorithm outside the catalog is named by its OID.
			name:  "X448 certificate",
			input: []byte(x448CertificatePEM),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindCertificate,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.x448Certificate.Raw),
						Name:     "x448",
						Certificate: &ftypes.CryptoCertificate{
							Subject:      "CN=x448",
							Issuer:       "CN=x448",
							SerialNumber: "3fca9c91f493c9e7513a668dc9314fa4f4e3d14d",
							NotBefore:    time.Date(2026, time.September, 30, 19, 21, 47, 0, time.UTC),
							NotAfter:     time.Date(2126, time.September, 6, 19, 21, 47, 0, time.UTC),
							Format:       ftypes.CryptoCertificateFormatX509,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: ed25519Algorithm.Descriptor(),
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: x448CertificateKey.Descriptor(),
							},
						},
					},
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(ed25519Algorithm),
				at(x448CertificateKey),
				at(x448Algorithm),
			},
		},
		{
			name:  "X25519 certificate",
			input: []byte(x25519CertificatePEM),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindCertificate,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, fixtures.x25519Certificate.Raw),
						Name:     "x25519",
						Certificate: &ftypes.CryptoCertificate{
							Subject:      "CN=x25519",
							Issuer:       "CN=x25519",
							SerialNumber: "69e31c0018584f08dc9107306731e34a279a4d8b",
							NotBefore:    time.Date(2026, time.October, 16, 7, 0, 21, 0, time.UTC),
							NotAfter:     time.Date(2126, time.September, 22, 7, 0, 21, 0, time.UTC),
							Format:       ftypes.CryptoCertificateFormatX509,
						},
						Relationships: []ftypes.CryptoRelationship{
							{
								Type:         ftypes.CryptoRelationshipSignedWith,
								RelatedAsset: ed25519Algorithm.Descriptor(),
							},
							{
								Type:         ftypes.CryptoRelationshipContains,
								RelatedAsset: x25519CertificateKey.Descriptor(),
							},
						},
					},
					FilePath: parsedFilePath,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(ed25519Algorithm),
				at(x25519CertificateKey),
				at(x25519Algorithm),
			},
		},
		{
			// crypto/x509 does not support P-192, so only the algorithm of the key is described.
			name:  "P-192 certificate PEM",
			input: []byte(p192CertificatePEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 certificate DER",
			input: decodePEM(t, p192CertificatePEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 public key",
			input: []byte(p192PublicKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 PKCS#8 private key",
			input: []byte(p192PKCS8PrivateKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 SEC 1 private key PEM",
			input: []byte(p192SEC1PrivateKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 SEC 1 private key DER",
			input: decodePEM(t, p192SEC1PrivateKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			// The algorithm is reported once per file.
			name:  "P-192 certificate and keys",
			input: []byte(p192CertificatePEM + p192PublicKeyPEM + p192PKCS8PrivateKeyPEM + p192SEC1PrivateKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 public key DER",
			input: decodePEM(t, p192PublicKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name:  "P-192 PKCS#8 private key DER",
			input: decodePEM(t, p192PKCS8PrivateKeyPEM),
			want:  []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name: "P-192 public key with a compressed point",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: p192PublicKeyDER(t, append([]byte{2}, make([]byte, 24)...)),
			}),
			want: []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name: "P-192 public key with a short point",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: p192PublicKeyDER(t, []byte{4, 1, 2}),
			}),
		},
		{
			name:  "P-192 certificate without a signature",
			input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p192UnsignedCertificate}),
		},
		{
			name: "P-192 SEC 1 private key without a curve",
			input: pem.EncodeToMemory(&pem.Block{
				Type: "EC PRIVATE KEY",
				Bytes: p192SEC1PrivateKeyDER(t, func(key *cryptox509.ECPrivateKey) {
					key.NamedCurveOID = nil
				}),
			}),
		},
		{
			name: "P-192 SEC 1 private key longer than 24 bytes",
			input: pem.EncodeToMemory(&pem.Block{
				Type: "EC PRIVATE KEY",
				Bytes: p192SEC1PrivateKeyDER(t, func(key *cryptox509.ECPrivateKey) {
					key.PrivateKey = make([]byte, 25)
				}),
			}),
		},
		{
			name: "P-192 SEC 1 private key of version 2",
			input: pem.EncodeToMemory(&pem.Block{
				Type: "EC PRIVATE KEY",
				Bytes: p192SEC1PrivateKeyDER(t, func(key *cryptox509.ECPrivateKey) {
					key.Version = 2
				}),
			}),
		},
		{
			// PKCS#8 names the curve in its algorithm, so the inner key may omit it.
			name: "P-192 PKCS#8 private key without a curve in SEC 1",
			input: pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY",
				Bytes: p192PKCS8PrivateKeyDER(t, p192SEC1PrivateKeyDER(t, func(key *cryptox509.ECPrivateKey) {
					key.NamedCurveOID = nil
				})),
			}),
			want: []ftypes.CryptoAsset{at(p192Algorithm)},
		},
		{
			name: "P-192 PKCS#8 private key with P-256 in SEC 1",
			input: pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY",
				Bytes: p192PKCS8PrivateKeyDER(t, p192SEC1PrivateKeyDER(t, func(key *cryptox509.ECPrivateKey) {
					key.NamedCurveOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
				})),
			}),
		},
		{
			// The key of a certificate and the same key on its own share an identity.
			name:  "Ed448 public key",
			input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixtures.ed448Certificate.RawSubjectPublicKeyInfo}),
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ed448CertificateKey,
					FilePath:        parsedFilePath,
					Format:          ftypes.CryptoKeyFormatPKIX,
					Encoding:        ftypes.CryptoEncodingPEM,
				},
				at(ed448Algorithm),
			},
		},
		{
			// A standalone key states the container it was found in, which the key of a
			// certificate has no equivalent of.
			name:  "public key",
			input: fixtures.publicPEM,
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
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
					},
					FilePath: parsedFilePath,
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(rsaAlgorithm),
			},
		},
		{
			name:  "DSA public key",
			input: fixtures.dsaDER,
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindKey,
						KeyType:  ftypes.CryptoKeyTypePublic,
						Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, fixtures.dsaDER),
						Name:     "DSA-2048 public key",
						Key: &ftypes.CryptoKey{
							Size: 2048,
						},
						Relationships: []ftypes.CryptoRelationship{{
							Type:         ftypes.CryptoRelationshipUsedWith,
							RelatedAsset: dsaAlgorithm.Descriptor(),
						}},
					},
					FilePath: parsedFilePath,
					Format:   ftypes.CryptoKeyFormatPKIX,
					Encoding: ftypes.CryptoEncodingDER,
				},
				at(dsaAlgorithm),
			},
		},
		{
			// The parser projects a private key to its public part, so only the key type differs.
			name:  "private key",
			input: fixtures.pkcs8PEM,
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindKey,
						KeyType:  ftypes.CryptoKeyTypePrivate,
						Identity: spkiIdentity(t, fixtures.rsaPublic),
						Name:     "RSA-2048 private key",
						Key: &ftypes.CryptoKey{
							Size: 2048,
						},
						Relationships: []ftypes.CryptoRelationship{{
							Type:         ftypes.CryptoRelationshipUsedWith,
							RelatedAsset: rsaAlgorithm.Descriptor(),
						}},
					},
					FilePath: parsedFilePath,
					Format:   ftypes.CryptoKeyFormatPKCS8,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(rsaAlgorithm),
			},
		},
		{
			name:  "multi-prime private key",
			input: fixtures.multiPrimePEM,
			want: []ftypes.CryptoAsset{
				{
					CryptoAssetInfo: ftypes.CryptoAssetInfo{
						Kind:     ftypes.CryptoKindKey,
						KeyType:  ftypes.CryptoKeyTypePrivate,
						Identity: spkiIdentity(t, fixtures.multiPrimePublic),
						Name:     "RSA-2048 private key",
						Key: &ftypes.CryptoKey{
							Size: 2048,
						},
						Relationships: []ftypes.CryptoRelationship{{
							Type:         ftypes.CryptoRelationshipUsedWith,
							RelatedAsset: rsaAlgorithm.Descriptor(),
						}},
					},
					FilePath: parsedFilePath,
					Format:   ftypes.CryptoKeyFormatPKCS1,
					Encoding: ftypes.CryptoEncodingPEM,
				},
				at(rsaAlgorithm),
			},
		},
		{
			name:  "encrypted PKCS#8 private key",
			input: fixtures.encryptedPEM,
			want: []ftypes.CryptoAsset{{
				CryptoAssetInfo: ftypes.CryptoAssetInfo{
					Kind:    ftypes.CryptoKindKey,
					KeyType: ftypes.CryptoKeyTypePrivate,
					// The container is identified by the DER inside the PEM block.
					Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedPKCS8SHA256, fixtures.encryptedDER),
					Name:     "Encrypted PKCS#8 private key",
					Key: &ftypes.CryptoKey{
						Encrypted: true,
					},
				},
				FilePath: parsedFilePath,
				Format:   ftypes.CryptoKeyFormatPKCS8,
				Encoding: ftypes.CryptoEncodingPEM,
			}},
		},
		{
			name:  "RFC 1423 encrypted private key",
			input: fixtures.rfc1423PEM,
			want: []ftypes.CryptoAsset{{
				CryptoAssetInfo: ftypes.CryptoAssetInfo{
					Kind:    ftypes.CryptoKindKey,
					KeyType: ftypes.CryptoKeyTypePrivate,
					// An RFC 1423 container is identified by the whole PEM block.
					Identity: ftypes.DigestIdentity(ftypes.CryptoMethodEncryptedRFC1423SHA256, fixtures.rfc1423PEM),
					Name:     "Encrypted PKCS#1 private key",
					Key: &ftypes.CryptoKey{
						Encrypted: true,
					},
				},
				FilePath: parsedFilePath,
				Format:   ftypes.CryptoKeyFormatPKCS1,
				Encoding: ftypes.CryptoEncodingPEM,
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
		wantPathLen    int64
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
	assert.Equal(t, signature, assets[1].CryptoAssetInfo)
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

	t.Run("certificates in one bundle keep their identities", func(t *testing.T) {
		bundle := parse(t, bytes.Join([][]byte{fixtures.certificatePEM, certificatePEM(fixtures.otherCertificate)}, nil))
		certificates := lo.Filter(bundle, func(asset ftypes.CryptoAsset, _ int) bool {
			return asset.Kind == ftypes.CryptoKindCertificate
		})
		require.Len(t, certificates, 2)
		assert.Equal(t, certificate[0].Identity, certificates[0].Identity)
		assert.Equal(t, otherCertificate[0].Identity, certificates[1].Identity)
	})

	t.Run("a certificate and a key file agree on the key they share", func(t *testing.T) {
		assert.Equal(t, publicKey[0].Identity, certificate[2].Identity)
	})
}

// parse describes a file and checks that every asset it reports is valid and relates only
// to assets reported with it.
func parse(t *testing.T, content []byte) []ftypes.CryptoAsset {
	t.Helper()

	assets, err := cryptox509.Parse(t.Context(), parsedFilePath, content)
	require.NoError(t, err)

	reported := set.New[ftypes.CryptoDescriptor]()
	for i, asset := range assets {
		require.NoErrorf(t, asset.Validate(), "asset %d", i)
		reported.Append(asset.Descriptor())
	}
	for i, asset := range assets {
		for _, relationship := range asset.Relationships {
			require.Truef(t, reported.Contains(relationship.RelatedAsset), "asset %d", i)
		}
	}
	return assets
}

// recognized reduces assets to what the input was recognized as. Algorithm assets are left
// out, because a key always carries the algorithm it belongs to.
func recognized(assets []ftypes.CryptoAsset) []found {
	var entries []found
	for _, asset := range assets {
		if asset.Kind == ftypes.CryptoKindAlgorithm {
			continue
		}
		entries = append(entries, found{
			kind:     asset.Kind,
			keyType:  asset.KeyType,
			method:   asset.Identity.Method,
			format:   asset.Format,
			encoding: asset.Encoding,
		})
	}
	return entries
}

// testFixtures is the parsed material every test reads.
type testFixtures struct {
	certificate        *stdx509.Certificate
	ecdsaCertificate   *stdx509.Certificate
	ed25519Certificate *stdx509.Certificate
	mldsaCertificate   *stdx509.Certificate
	ed448Certificate   *stdx509.Certificate
	x448Certificate    *stdx509.Certificate
	x25519Certificate  *stdx509.Certificate
	// malformedKeyCertificate carries an X448 key whose SubjectPublicKeyInfo has an extra
	// element, which crypto/x509 accepts for a key it does not decode.
	malformedKeyCertificate *stdx509.Certificate
	pathLenZero             *stdx509.Certificate
	noCommonName            *stdx509.Certificate
	otherCertificate        *stdx509.Certificate
	pssCertificate          *stdx509.Certificate
	rsaPublic               *rsa.PublicKey
	multiPrimePublic        *rsa.PublicKey
	multiPrimePEM           []byte
	certificateDER          []byte
	certificatePEM          []byte
	pkcs1DER                []byte
	pkcs8DER                []byte
	pkcs8PEM                []byte
	sec1DER                 []byte
	publicDER               []byte
	publicPEM               []byte
	encryptedDER            []byte
	encryptedPEM            []byte
	rfc1423PEM              []byte
	ed25519DER              []byte
	mldsaDER                []byte
	dsaDER                  []byte
	x25519PKCS8DER          []byte
	x25519PKIXDER           []byte
	// malformedEd25519PKIXDER is an Ed25519 key with a public value of the wrong length.
	malformedEd25519PKIXDER []byte
	// malformedX25519PKIXDER is an X25519 key with a public value of the wrong length.
	malformedX25519PKIXDER []byte
	csrDER                 []byte
	csrPEM                 []byte
	crlDER                 []byte
	crlPEM                 []byte
	unsupportedDER         []byte
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

// sharedMultiPrimeRSAKey is a 2048-bit key with three primes, generated once for the
// package like sharedRSAKey.
var sharedMultiPrimeRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func newFixtures(t *testing.T) testFixtures {
	t.Helper()

	rsaKey := sharedRSAKey()
	multiPrimeKey := sharedMultiPrimeRSAKey()
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
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

	// A certificate whose key algorithm carries the curve of the key as its parameter.
	ecdsaCertificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "ec.example.test"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}, ecdsaKey)

	// A certificate that uses one OID for both its signature and its key.
	ed25519Certificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "ed25519.example.test"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}, ed25519Key)

	mldsaCertificate := newCertificate(t, &stdx509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "mldsa.example.test"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}, mldsaKey)

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
	ed25519DER, err := stdx509.MarshalPKCS8PrivateKey(ed25519Key)
	require.NoError(t, err)
	mldsaDER, err := stdx509.MarshalPKCS8PrivateKey(mldsaKey)
	require.NoError(t, err)
	// crypto/x509 parses a DSA key but cannot encode one, so the input comes from pkg/crypto.
	dsaDER, err := crypto.MarshalPublicKey(&dsa.PublicKey{
		Parameters: dsa.Parameters{
			// A 2048-bit p and a 224-bit q, so that (L, N) is a realistic pair. The group is
			// not a valid one, which nothing on this path checks.
			P: new(big.Int).Lsh(big.NewInt(1), 2047),
			Q: new(big.Int).Lsh(big.NewInt(1), 223),
			G: big.NewInt(2),
		},
		Y: big.NewInt(4),
	})
	require.NoError(t, err)

	// Encrypted containers, kept opaque because the parser only validates the envelope.
	encryptedDER, err := asn1.Marshal(cryptox509.EncryptedPrivateKeyInfo{
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
	x448Certificate := parseCertificatePEM(t, x448CertificatePEM)
	var spki asn1.RawValue
	_, err = asn1.Unmarshal(x448Certificate.RawSubjectPublicKeyInfo, &spki)
	require.NoError(t, err)
	spki.Bytes = bytes.Join([][]byte{spki.Bytes, asn1.NullBytes}, nil)
	spki.FullBytes = nil
	malformedSPKI, err := asn1.Marshal(spki)
	require.NoError(t, err)
	// The signature no longer matches, which crypto/x509 does not check when parsing.
	malformedKeyCertificate := withSubjectPublicKeyInfo(t, x448Certificate, malformedSPKI)

	unsupportedDER, err := asn1.Marshal(struct {
		Value string
	}{Value: "unsupported"})
	require.NoError(t, err)

	return testFixtures{
		certificate:             certificate,
		ecdsaCertificate:        ecdsaCertificate,
		ed25519Certificate:      ed25519Certificate,
		mldsaCertificate:        mldsaCertificate,
		ed448Certificate:        parseCertificatePEM(t, ed448CertificatePEM),
		x448Certificate:         x448Certificate,
		x25519Certificate:       parseCertificatePEM(t, x25519CertificatePEM),
		malformedKeyCertificate: malformedKeyCertificate,
		pathLenZero:             pathLenZero,
		noCommonName:            noCommonName,
		otherCertificate:        otherCertificate,
		pssCertificate:          pssCertificate,
		rsaPublic:               &rsaKey.PublicKey,
		multiPrimePublic:        &multiPrimeKey.PublicKey,
		multiPrimePEM:           pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: stdx509.MarshalPKCS1PrivateKey(multiPrimeKey)}),
		certificateDER:          certificate.Raw,
		certificatePEM:          certificatePEM(certificate),
		pkcs1DER:                stdx509.MarshalPKCS1PrivateKey(rsaKey),
		pkcs8DER:                pkcs8DER,
		pkcs8PEM:                pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
		sec1DER:                 sec1DER,
		publicDER:               publicDER,
		publicPEM:               pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		encryptedDER:            encryptedDER,
		encryptedPEM:            pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER}),
		rfc1423PEM:              rfc1423PEM,
		ed25519DER:              ed25519DER,
		mldsaDER:                mldsaDER,
		dsaDER:                  dsaDER,
		x25519PKCS8DER:          x25519PKCS8DER,
		x25519PKIXDER:           x25519PKIXDER,
		malformedEd25519PKIXDER: marshalSPKI(t, asn1.ObjectIdentifier{1, 3, 101, 112}, []byte{1}),
		malformedX25519PKIXDER:  marshalSPKI(t, asn1.ObjectIdentifier{1, 3, 101, 110}, []byte{1}),
		csrDER:                  csrDER,
		csrPEM:                  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		crlDER:                  crlDER,
		crlPEM:                  pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}),
		unsupportedDER:          unsupportedDER,
	}
}

// newCertificate self-signs a template and parses it back, because a template alone has
// no raw DER to identify and no parsed basic constraints.
func newCertificate(t *testing.T, template *stdx509.Certificate, key stdcrypto.Signer) *stdx509.Certificate {
	t.Helper()

	der, err := stdx509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	certificate, err := stdx509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func parseCertificatePEM(t *testing.T, content string) *stdx509.Certificate {
	t.Helper()

	certificate, err := stdx509.ParseCertificate(decodePEM(t, content))
	require.NoError(t, err)
	return certificate
}

// decodePEM returns the DER of the first PEM block in content.
func decodePEM(t *testing.T, content string) []byte {
	t.Helper()

	block, _ := pem.Decode([]byte(content))
	require.NotNil(t, block)
	return block.Bytes
}

// p192PublicKeyDER encodes a SubjectPublicKeyInfo on P-192 with point as its public key.
func p192PublicKeyDER(t *testing.T, point []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm:        p192AlgorithmIdentifier(t),
		SubjectPublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	require.NoError(t, err)
	return der
}

// p192SEC1PrivateKeyDER encodes the P-192 key of the fixtures in SEC 1 after applying
// mutate to it.
func p192SEC1PrivateKeyDER(t *testing.T, mutate func(*cryptox509.ECPrivateKey)) []byte {
	t.Helper()

	var key cryptox509.ECPrivateKey
	_, err := asn1.Unmarshal(decodePEM(t, p192SEC1PrivateKeyPEM), &key)
	require.NoError(t, err)
	mutate(&key)
	der, err := asn1.Marshal(key)
	require.NoError(t, err)
	return der
}

// p192PKCS8PrivateKeyDER encodes a PKCS#8 private key on P-192 that holds sec1.
func p192PKCS8PrivateKeyDER(t *testing.T, sec1 []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(cryptox509.PKCS8PrivateKey{
		Algo:       p192AlgorithmIdentifier(t),
		PrivateKey: sec1,
	})
	require.NoError(t, err)
	return der
}

// p192AlgorithmIdentifier returns the algorithm identifier of an EC key on P-192.
func p192AlgorithmIdentifier(t *testing.T) pkix.AlgorithmIdentifier {
	t.Helper()

	parameters, err := asn1.Marshal(cryptox509.OIDNamedCurveP192)
	require.NoError(t, err)
	return pkix.AlgorithmIdentifier{
		Algorithm:  cryptox509.OIDECPublicKey,
		Parameters: asn1.RawValue{FullBytes: parameters},
	}
}

// marshalSPKI encodes a SubjectPublicKeyInfo with the given algorithm OID and public key bytes.
func marshalSPKI(t *testing.T, oid asn1.ObjectIdentifier, publicKey []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm:        pkix.AlgorithmIdentifier{Algorithm: oid},
		SubjectPublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
	})
	require.NoError(t, err)
	return der
}

// withSubjectPublicKeyInfo re-encodes a certificate with spki in place of its own and
// parses it back.
func withSubjectPublicKeyInfo(t *testing.T, certificate *stdx509.Certificate, spki []byte) *stdx509.Certificate {
	t.Helper()

	tbs := replaceInSequence(t, certificate.RawTBSCertificate, certificate.RawSubjectPublicKeyInfo, spki)
	parsed, err := stdx509.ParseCertificate(replaceInSequence(t, certificate.Raw, certificate.RawTBSCertificate, tbs))
	require.NoError(t, err)
	return parsed
}

// replaceInSequence re-encodes a DER sequence with old replaced by replacement in its
// content.
func replaceInSequence(t *testing.T, sequence, old, replacement []byte) []byte {
	t.Helper()

	var raw asn1.RawValue
	_, err := asn1.Unmarshal(sequence, &raw)
	require.NoError(t, err)
	require.True(t, bytes.Contains(raw.Bytes, old), "sequence does not contain the replaced element")
	raw.Bytes = bytes.Replace(raw.Bytes, old, replacement, 1)
	raw.FullBytes = nil
	der, err := asn1.Marshal(raw)
	require.NoError(t, err)
	return der
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
