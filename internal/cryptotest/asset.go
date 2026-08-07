// Package cryptotest provides cryptographic asset fixtures for tests.
package cryptotest

import (
	"strings"

	cryptotypes "github.com/aquasecurity/trivy/pkg/crypto"
)

// Option customizes an Asset fixture.
type Option func(*cryptotypes.CryptoAsset)

// WithMutate applies mutate after constructing a complete Asset fixture.
func WithMutate(mutate func(*cryptotypes.CryptoAsset)) Option {
	return mutate
}

// CertificateAsset returns a valid certificate asset.
func CertificateAsset(opts ...Option) cryptotypes.CryptoAsset {
	asset := cryptotypes.CryptoAsset{
		Kind: cryptotypes.CryptoKindCertificate,
		Identity: cryptotypes.CryptoIdentity{
			Method: cryptotypes.CryptoMethodSHA256,
			Value:  strings.Repeat("a", 64),
		},
		Name:     "example.test",
		FilePath: "/etc/example.pem",
		Certificate: &cryptotypes.CryptoCertificate{
			Subject:      "CN=example.test",
			Issuer:       "CN=Example Test CA",
			SerialNumber: "1",
			Format:       cryptotypes.CryptoCertificateFormatX509,
		},
	}
	return applyOptions(asset, opts)
}

// PublicKeyAsset returns a valid public key asset.
func PublicKeyAsset(opts ...Option) cryptotypes.CryptoAsset {
	asset := cryptotypes.CryptoAsset{
		Kind:    cryptotypes.CryptoKindKey,
		KeyType: cryptotypes.CryptoKeyTypePublic,
		Identity: cryptotypes.CryptoIdentity{
			Method: cryptotypes.CryptoMethodSPKISHA256,
			Value:  strings.Repeat("b", 64),
		},
		FilePath: "/etc/example-public.pem",
		Key: &cryptotypes.CryptoKey{
			Size:     2048,
			Format:   cryptotypes.CryptoKeyFormatPKIX,
			Encoding: cryptotypes.CryptoEncodingPEM,
		},
	}
	return applyOptions(asset, opts)
}

// PrivateKeyAsset returns a valid private key asset.
func PrivateKeyAsset(opts ...Option) cryptotypes.CryptoAsset {
	asset := PublicKeyAsset()
	asset.KeyType = cryptotypes.CryptoKeyTypePrivate
	asset.FilePath = "/etc/example-private.pem"
	asset.Key.Format = cryptotypes.CryptoKeyFormatPKCS8
	return applyOptions(asset, opts)
}

// EncryptedPrivateKeyAsset returns a valid encrypted private key asset.
func EncryptedPrivateKeyAsset(opts ...Option) cryptotypes.CryptoAsset {
	asset := PrivateKeyAsset()
	asset.Identity.Method = cryptotypes.CryptoMethodEncryptedPKCS8SHA256
	asset.FilePath = "/etc/example-encrypted-private.pem"
	asset.Key.Encrypted = true
	return applyOptions(asset, opts)
}

// AlgorithmAsset returns a valid algorithm asset.
func AlgorithmAsset(opts ...Option) cryptotypes.CryptoAsset {
	asset := cryptotypes.CryptoAsset{
		Kind: cryptotypes.CryptoKindAlgorithm,
		Identity: cryptotypes.CryptoIdentity{
			Method: cryptotypes.CryptoMethodOID,
			Value:  "1.2.840.113549.1.1.1",
		},
		Name:     "RSA",
		FilePath: "/etc/example-algorithm.pem",
		Algorithm: &cryptotypes.CryptoAlgorithm{
			Family:    "RSA",
			Primitive: cryptotypes.CryptoPrimitivePKE,
		},
	}
	return applyOptions(asset, opts)
}

func applyOptions(asset cryptotypes.CryptoAsset, opts []Option) cryptotypes.CryptoAsset {
	for _, opt := range opts {
		opt(&asset)
	}
	return asset
}
