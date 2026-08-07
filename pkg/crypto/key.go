package crypto

// KeyType identifies whether a key is public or private.
type KeyType string

const (
	// KeyTypePublic identifies a public key.
	KeyTypePublic KeyType = "public"
	// KeyTypePrivate identifies a private key.
	KeyTypePrivate KeyType = "private"
)

// Encoding identifies the outer encoding of source cryptographic data.
type Encoding string

const (
	// EncodingPEM identifies PEM encoding.
	EncodingPEM Encoding = "PEM"
	// EncodingDER identifies DER encoding.
	EncodingDER Encoding = "DER"
)

// KeyFormat identifies the serialization format of a standalone key object.
type KeyFormat string

const (
	// KeyFormatPKCS1 identifies the PKCS#1 key format.
	KeyFormatPKCS1 KeyFormat = "PKCS#1"
	// KeyFormatPKCS8 identifies the PKCS#8 key format.
	KeyFormatPKCS8 KeyFormat = "PKCS#8"
	// KeyFormatSEC1 identifies the SEC1 key format.
	KeyFormatSEC1 KeyFormat = "SEC1"
	// KeyFormatPKIX identifies the PKIX public key format.
	KeyFormatPKIX KeyFormat = "PKIX"
)

// Key contains key-specific metadata.
type Key struct {
	Size  int    `json:",omitempty"`
	Curve string `json:",omitempty"`

	// Format identifies the source standalone key container. It is empty when
	// the key is derived from an enclosing object, such as a certificate.
	Format KeyFormat `json:",omitempty"`
	// Encoding identifies the source standalone key encoding. It is empty when
	// the key is derived from an enclosing object, such as a certificate.
	Encoding Encoding `json:",omitempty"`

	Encrypted bool `json:",omitempty"`
}
