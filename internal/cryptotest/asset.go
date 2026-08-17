// Package cryptotest provides cryptographic asset fixtures for tests.
package cryptotest

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Option customizes an Asset fixture.
type Option func(*types.CryptoAsset)

// WithMutate applies mutate after constructing a complete Asset fixture.
func WithMutate(mutate func(*types.CryptoAsset)) Option {
	return mutate
}

// CertificateAsset returns a valid certificate asset.
func CertificateAsset(opts ...Option) types.CryptoAsset {
	asset := types.CryptoAsset{
		Kind: types.CryptoKindCertificate,
		Identity: types.CryptoIdentity{
			Method: types.CryptoMethodSHA256,
			Value:  strings.Repeat("a", 64),
		},
		Name:     "example.test",
		FilePath: "/etc/example.pem",
		Certificate: &types.CryptoCertificate{
			Subject:      "CN=example.test",
			Issuer:       "CN=Example Test CA",
			SerialNumber: "1",
			Format:       types.CryptoCertificateFormatX509,
			Encoding:     types.CryptoEncodingPEM,
		},
	}
	return applyOptions(asset, opts)
}

// PublicKeyAsset returns a valid public key asset.
func PublicKeyAsset(opts ...Option) types.CryptoAsset {
	asset := types.CryptoAsset{
		Kind:    types.CryptoKindKey,
		KeyType: types.CryptoKeyTypePublic,
		Identity: types.CryptoIdentity{
			Method: types.CryptoMethodSPKISHA256,
			Value:  strings.Repeat("b", 64),
		},
		FilePath: "/etc/example-public.pem",
		Key: &types.CryptoKey{
			Size:     2048,
			Format:   types.CryptoKeyFormatPKIX,
			Encoding: types.CryptoEncodingPEM,
		},
	}
	return applyOptions(asset, opts)
}

// PrivateKeyAsset returns a valid private key asset.
func PrivateKeyAsset(opts ...Option) types.CryptoAsset {
	asset := PublicKeyAsset()
	asset.KeyType = types.CryptoKeyTypePrivate
	asset.FilePath = "/etc/example-private.pem"
	asset.Key.Format = types.CryptoKeyFormatPKCS8
	return applyOptions(asset, opts)
}

// EncryptedPrivateKeyAsset returns a valid encrypted private key asset.
func EncryptedPrivateKeyAsset(opts ...Option) types.CryptoAsset {
	asset := PrivateKeyAsset()
	asset.Identity.Method = types.CryptoMethodEncryptedPKCS8SHA256
	asset.FilePath = "/etc/example-encrypted-private.pem"
	asset.Key.Encrypted = true
	return applyOptions(asset, opts)
}

// RFC1423EncryptedPrivateKeyAsset returns a valid RFC 1423 encrypted private key asset.
func RFC1423EncryptedPrivateKeyAsset(opts ...Option) types.CryptoAsset {
	asset := EncryptedPrivateKeyAsset()
	asset.Identity.Method = types.CryptoMethodEncryptedRFC1423SHA256
	asset.Key.Format = types.CryptoKeyFormatPKCS1
	return applyOptions(asset, opts)
}

// AlgorithmAsset returns a valid algorithm asset.
func AlgorithmAsset(opts ...Option) types.CryptoAsset {
	asset := types.CryptoAsset{
		Kind: types.CryptoKindAlgorithm,
		Identity: types.CryptoIdentity{
			Method: types.CryptoMethodOID,
			Value:  "1.2.840.113549.1.1.1",
		},
		Name:     "RSA",
		FilePath: "/etc/example-algorithm.pem",
		Algorithm: &types.CryptoAlgorithm{
			Family:    "RSA",
			Primitive: types.CryptoPrimitivePKE,
		},
	}
	return applyOptions(asset, opts)
}

func applyOptions(asset types.CryptoAsset, opts []Option) types.CryptoAsset {
	for _, opt := range opts {
		opt(&asset)
	}
	return asset
}
