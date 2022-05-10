package jws

// PublicHeaders returns the public headers in a JWS
func (s Signature) PublicHeaders() Headers {
	return s.Headers
}

// ProtectedHeaders returns the protected headers in a JWS
func (s Signature) ProtectedHeaders() Headers {
	return s.Protected
}

// GetSignature returns the signature in a JWS
func (s Signature) GetSignature() []byte {
	return s.Signature
}

// GetPayload returns the payload in a JWS
func (m Message) GetPayload() []byte {
	return m.Payload
}

// GetSignatures returns the all signatures in a JWS
func (m Message) GetSignatures() []*Signature {
	return m.Signatures
}
