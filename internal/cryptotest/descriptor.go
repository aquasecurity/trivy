package cryptotest

import "github.com/aquasecurity/trivy/pkg/crypto"

// CertificateDescriptor returns the descriptor of CertificateAsset.
func CertificateDescriptor() crypto.Descriptor {
	asset := CertificateAsset()
	return asset.Descriptor()
}

// PublicKeyDescriptor returns the descriptor of PublicKeyAsset.
func PublicKeyDescriptor() crypto.Descriptor {
	asset := PublicKeyAsset()
	return asset.Descriptor()
}

// PrivateKeyDescriptor returns the descriptor of PrivateKeyAsset.
func PrivateKeyDescriptor() crypto.Descriptor {
	asset := PrivateKeyAsset()
	return asset.Descriptor()
}

// EncryptedPrivateKeyDescriptor returns the descriptor of EncryptedPrivateKeyAsset.
func EncryptedPrivateKeyDescriptor() crypto.Descriptor {
	asset := EncryptedPrivateKeyAsset()
	return asset.Descriptor()
}

// AlgorithmDescriptor returns the descriptor of AlgorithmAsset.
func AlgorithmDescriptor() crypto.Descriptor {
	asset := AlgorithmAsset()
	return asset.Descriptor()
}
