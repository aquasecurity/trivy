package crypto

// Primitive identifies the cryptographic primitive provided by an algorithm.
type Primitive string

const (
	// PrimitiveUnknown identifies an algorithm with an unknown primitive.
	PrimitiveUnknown Primitive = "unknown"
	// PrimitiveSignature identifies a digital signature algorithm.
	PrimitiveSignature Primitive = "signature"
	// PrimitivePKE identifies a public-key encryption algorithm.
	PrimitivePKE Primitive = "pke"
)

// Algorithm contains algorithm-specific metadata.
type Algorithm struct {
	Family    string    `json:",omitempty"`
	Primitive Primitive `json:",omitempty"`
}
