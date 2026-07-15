package crypto

// KeyType identifies whether a key is public or private.
type KeyType string

const (
	// KeyTypePublic identifies a public key.
	KeyTypePublic KeyType = "public"
	// KeyTypePrivate identifies a private key.
	KeyTypePrivate KeyType = "private"
)

// Encoding identifies the outer encoding of a key.
type Encoding string

const (
	// EncodingPEM identifies PEM encoding.
	EncodingPEM Encoding = "PEM"
	// EncodingDER identifies DER encoding.
	EncodingDER Encoding = "DER"
)

// KeyFormat identifies the serialization format of a key.
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
	Size      int       `json:",omitempty"`
	Curve     string    `json:",omitempty"`
	Format    KeyFormat `json:",omitempty"`
	Encoding  Encoding  `json:",omitempty"`
	Encrypted bool      `json:",omitempty"`
}
