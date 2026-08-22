package types

// CryptoKeyType identifies whether a key is public or private.
type CryptoKeyType string

const (
	// CryptoKeyTypePublic identifies a public key.
	CryptoKeyTypePublic CryptoKeyType = "public"
	// CryptoKeyTypePrivate identifies a private key.
	CryptoKeyTypePrivate CryptoKeyType = "private"
)

// CryptoKeyFormat identifies the serialization format of a standalone key object.
type CryptoKeyFormat string

const (
	// CryptoKeyFormatPKCS1 identifies the PKCS#1 key format.
	CryptoKeyFormatPKCS1 CryptoKeyFormat = "PKCS#1"
	// CryptoKeyFormatPKCS8 identifies the PKCS#8 key format.
	CryptoKeyFormatPKCS8 CryptoKeyFormat = "PKCS#8"
	// CryptoKeyFormatSEC1 identifies the SEC1 key format.
	CryptoKeyFormatSEC1 CryptoKeyFormat = "SEC1"
	// CryptoKeyFormatPKIX identifies the PKIX public key format.
	CryptoKeyFormatPKIX CryptoKeyFormat = "PKIX"
)

// CryptoKey contains key-specific metadata. The container the key was stored in belongs
// to CryptoAsset, because it describes the file rather than the key.
type CryptoKey struct {
	Size  int    `json:",omitempty"`
	Curve string `json:",omitempty"`

	Encrypted bool `json:",omitempty"`
}
