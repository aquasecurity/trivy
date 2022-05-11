package jws

// Message represents a full JWS encoded message. Flattened serialization
// is not supported as a struct, but rather it's represented as a
// Message struct with only one `Signature` element.
//
// Do not expect to use the Message object to verify or construct a
// signed payloads with. You should only use this when you want to actually
// want to programmatically view the contents for the full JWS Payload.
//
// To sign and verify, use the appropriate `SignWithOption()` nad `Verify()` functions
type Message struct {
	Payload    []byte       `json:"payload"`
	Signatures []*Signature `json:"signatures,omitempty"`
}

// Signature represents the headers and signature of a JWS message
type Signature struct {
	Headers   Headers `json:"header,omitempty"`    // Unprotected Headers
	Protected Headers `json:"Protected,omitempty"` // Protected Headers
	Signature []byte  `json:"signature,omitempty"` // GetSignature
}
