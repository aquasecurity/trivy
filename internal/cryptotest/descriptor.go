package cryptotest

import "github.com/aquasecurity/trivy/pkg/fanal/types"

// CertificateDescriptor returns the descriptor of CertificateAsset.
func CertificateDescriptor() types.CryptoDescriptor {
	asset := CertificateAsset()
	return asset.Descriptor()
}

// PublicKeyDescriptor returns the descriptor of PublicKeyAsset.
func PublicKeyDescriptor() types.CryptoDescriptor {
	asset := PublicKeyAsset()
	return asset.Descriptor()
}

// PrivateKeyDescriptor returns the descriptor of PrivateKeyAsset.
func PrivateKeyDescriptor() types.CryptoDescriptor {
	asset := PrivateKeyAsset()
	return asset.Descriptor()
}

// EncryptedPrivateKeyDescriptor returns the descriptor of EncryptedPrivateKeyAsset.
func EncryptedPrivateKeyDescriptor() types.CryptoDescriptor {
	asset := EncryptedPrivateKeyAsset()
	return asset.Descriptor()
}

// AlgorithmDescriptor returns the descriptor of AlgorithmAsset.
func AlgorithmDescriptor() types.CryptoDescriptor {
	asset := AlgorithmAsset()
	return asset.Descriptor()
}
