package types

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
//
// The security levels are nominal estimates for the algorithm and its parameters, not a
// statement about an implementation or about policy approval. A nil level is not estimated.
type CryptoAlgorithm struct {
	Family    string `json:",omitempty"`
	Primitive CryptoPrimitive

	// ClassicalSecurityLevel is the classical security strength in bits.
	ClassicalSecurityLevel *int `json:",omitempty"`
	// NISTQuantumSecurityLevel is the NIST post-quantum security category from 1 to 6, or 0
	// for an algorithm that meets none of them.
	NISTQuantumSecurityLevel *int `json:",omitempty"`
}
