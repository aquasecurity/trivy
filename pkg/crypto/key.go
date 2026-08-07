package crypto

// CryptoKeyType identifies whether a key is public or private.
type CryptoKeyType string

const (
	// CryptoKeyTypePublic identifies a public key.
	CryptoKeyTypePublic CryptoKeyType = "public"
	// CryptoKeyTypePrivate identifies a private key.
	CryptoKeyTypePrivate CryptoKeyType = "private"
)

// CryptoEncoding identifies the outer encoding of source cryptographic data.
type CryptoEncoding string

const (
	// CryptoEncodingPEM identifies PEM encoding.
	CryptoEncodingPEM CryptoEncoding = "PEM"
	// CryptoEncodingDER identifies DER encoding.
	CryptoEncodingDER CryptoEncoding = "DER"
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

// CryptoKey contains key-specific metadata.
type CryptoKey struct {
	Size  int    `json:",omitempty"`
	Curve string `json:",omitempty"`

	// Format identifies the source standalone key container. It is empty when
	// the key is derived from an enclosing object, such as a certificate.
	Format CryptoKeyFormat `json:",omitempty"`
	// Encoding identifies the source standalone key encoding. It is empty when
	// the key is derived from an enclosing object, such as a certificate.
	Encoding CryptoEncoding `json:",omitempty"`

	Encrypted bool `json:",omitempty"`
}
