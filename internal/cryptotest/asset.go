// Package cryptotest provides cryptographic asset fixtures for tests.
package cryptotest

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/crypto"
)

// Option customizes an Asset fixture.
type Option func(*crypto.Asset)

// WithMutate applies mutate after constructing a complete Asset fixture.
func WithMutate(mutate func(*crypto.Asset)) Option {
	return mutate
}

// CertificateAsset returns a valid certificate asset.
func CertificateAsset(opts ...Option) crypto.Asset {
	asset := crypto.Asset{
		Kind: crypto.KindCertificate,
		Identity: crypto.Identity{
			Method: crypto.MethodSHA256,
			Value:  strings.Repeat("a", 64),
		},
		Name:     "example.test",
		FilePath: "/etc/example.pem",
		Certificate: &crypto.Certificate{
			Subject:      "CN=example.test",
			Issuer:       "CN=Example Test CA",
			SerialNumber: "1",
			Format:       crypto.CertificateFormatX509,
		},
	}
	return applyOptions(asset, opts)
}

// PublicKeyAsset returns a valid public key asset.
func PublicKeyAsset(opts ...Option) crypto.Asset {
	asset := crypto.Asset{
		Kind:    crypto.KindKey,
		KeyType: crypto.KeyTypePublic,
		Identity: crypto.Identity{
			Method: crypto.MethodSPKISHA256,
			Value:  strings.Repeat("b", 64),
		},
		FilePath: "/etc/example-public.pem",
		Key: &crypto.Key{
			Size:     2048,
			Format:   crypto.KeyFormatPKIX,
			Encoding: crypto.EncodingPEM,
		},
	}
	return applyOptions(asset, opts)
}

// PrivateKeyAsset returns a valid private key asset.
func PrivateKeyAsset(opts ...Option) crypto.Asset {
	asset := PublicKeyAsset()
	asset.KeyType = crypto.KeyTypePrivate
	asset.FilePath = "/etc/example-private.pem"
	asset.Key.Format = crypto.KeyFormatPKCS8
	return applyOptions(asset, opts)
}

// EncryptedPrivateKeyAsset returns a valid encrypted private key asset.
func EncryptedPrivateKeyAsset(opts ...Option) crypto.Asset {
	asset := PrivateKeyAsset()
	asset.Identity.Method = crypto.MethodEncryptedPKCS8SHA256
	asset.FilePath = "/etc/example-encrypted-private.pem"
	asset.Key.Encrypted = true
	return applyOptions(asset, opts)
}

// AlgorithmAsset returns a valid algorithm asset.
func AlgorithmAsset(opts ...Option) crypto.Asset {
	asset := crypto.Asset{
		Kind: crypto.KindAlgorithm,
		Identity: crypto.Identity{
			Method: crypto.MethodOID,
			Value:  "1.2.840.113549.1.1.1",
		},
		Name:     "RSA",
		FilePath: "/etc/example-algorithm.pem",
		Algorithm: &crypto.Algorithm{
			Family:    "RSA",
			Primitive: crypto.PrimitivePKE,
		},
	}
	return applyOptions(asset, opts)
}

func applyOptions(asset crypto.Asset, opts []Option) crypto.Asset {
	for _, opt := range opts {
		opt(&asset)
	}
	return asset
}
