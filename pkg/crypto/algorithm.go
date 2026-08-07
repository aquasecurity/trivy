package crypto

// CryptoPrimitive identifies the cryptographic primitive provided by an algorithm.
type CryptoPrimitive string

const (
	// CryptoPrimitiveUnknown identifies an algorithm with an unknown primitive.
	CryptoPrimitiveUnknown CryptoPrimitive = "unknown"
	// CryptoPrimitiveSignature identifies a digital signature algorithm.
	CryptoPrimitiveSignature CryptoPrimitive = "signature"
	// CryptoPrimitivePKE identifies a public-key encryption algorithm.
	CryptoPrimitivePKE CryptoPrimitive = "pke"
)

// CryptoAlgorithm contains algorithm-specific metadata.
type CryptoAlgorithm struct {
	Family    string          `json:",omitempty"`
	Primitive CryptoPrimitive `json:",omitempty"`
}
