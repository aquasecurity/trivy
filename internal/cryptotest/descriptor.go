package cryptotest

import cryptotypes "github.com/aquasecurity/trivy/pkg/crypto"

// CertificateDescriptor returns the descriptor of CertificateAsset.
func CertificateDescriptor() cryptotypes.CryptoDescriptor {
	asset := CertificateAsset()
	return asset.Descriptor()
}

// PublicKeyDescriptor returns the descriptor of PublicKeyAsset.
func PublicKeyDescriptor() cryptotypes.CryptoDescriptor {
	asset := PublicKeyAsset()
	return asset.Descriptor()
}

// PrivateKeyDescriptor returns the descriptor of PrivateKeyAsset.
func PrivateKeyDescriptor() cryptotypes.CryptoDescriptor {
	asset := PrivateKeyAsset()
	return asset.Descriptor()
}

// EncryptedPrivateKeyDescriptor returns the descriptor of EncryptedPrivateKeyAsset.
func EncryptedPrivateKeyDescriptor() cryptotypes.CryptoDescriptor {
	asset := EncryptedPrivateKeyAsset()
	return asset.Descriptor()
}

// AlgorithmDescriptor returns the descriptor of AlgorithmAsset.
func AlgorithmDescriptor() cryptotypes.CryptoDescriptor {
	asset := AlgorithmAsset()
	return asset.Descriptor()
}
