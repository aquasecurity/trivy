package crypto

// MarshalPublicKey exposes the SubjectPublicKeyInfo encoder to the tests,
// which need the canonical form a key is identified by.
var MarshalPublicKey = marshalPublicKey
