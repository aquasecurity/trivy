package crypto

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

// algorithm is the hand-maintained knowledge about an OID: the name and family it
// carries in the CycloneDX cryptography vocabulary, the primitive it provides, and the
// key property that distinguishes assets sharing it.
//
// An OID whose purpose cannot be decided carries no family and an unknown primitive.
// RFC 3279 section 2.3.1 states that rsaEncryption identifies both signature and
// encryption keys, and id-ecPublicKey is shared by ECDSA and ECDH just as widely.
// Naming a family for either would assert a purpose the certificate does not state.
//
// A name is a base name: an algorithm with a parameter is named together with the value
// of that parameter, such as RSA-2048.
type algorithm struct {
	name      string
	family    string
	primitive ftypes.CryptoPrimitive
	parameter ftypes.CryptoAlgorithmParameter
}

// algorithms maps the OIDs that appear in the certificates and keys this package
// describes. An OID is read out of the DER rather than taken from a crypto/x509
// enumeration, so an algorithm the standard library does not recognize reaches this table
// as well.
//
// A name follows the naming pattern the CycloneDX cryptography vocabulary defines for
// the family: RSASSA-PKCS1 carries the pattern RSA-PKCS1-1.5[-{digestAlgorithm}][-{keyLength}],
// which yields RSA-PKCS1-1.5-SHA-256 for sha256WithRSAEncryption. A signature name stops
// at the digest: the key length in the pattern describes the key that produced the
// signature, and that key belongs to the issuer, while a certificate carries the key of
// its subject.
//
// An OID with no family has no pattern to follow, because the vocabulary defines one per
// family. Its name is built by the same rule as every other: the base name carries the
// value of the parameter that distinguishes the asset, which yields RSA-2048 and EC-P-256.
//
// RSA-PSS is absent on purpose: its variants share one OID and differ only in the
// signature parameters, so identifying it needs parameter-aware handling.
var algorithms = map[string]algorithm{
	// Certificate signature algorithms.
	"1.2.840.113549.1.1.4": {
		name:      "RSA-PKCS1-1.5-MD5",
		family:    "RSASSA-PKCS1",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.113549.1.1.5": {
		name:      "RSA-PKCS1-1.5-SHA-1",
		family:    "RSASSA-PKCS1",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.113549.1.1.11": {
		name:      "RSA-PKCS1-1.5-SHA-256",
		family:    "RSASSA-PKCS1",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.113549.1.1.12": {
		name:      "RSA-PKCS1-1.5-SHA-384",
		family:    "RSASSA-PKCS1",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.113549.1.1.13": {
		name:      "RSA-PKCS1-1.5-SHA-512",
		family:    "RSASSA-PKCS1",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	// The ISO arc carries a second OID for SHA-1 with RSA, which makecert.exe has been
	// known to produce. The two OIDs name one algorithm but stay two assets, because an
	// algorithm is identified by the OID the certificate carries.
	"1.3.14.3.2.29": {
		name:      "RSA-PKCS1-1.5-SHA-1",
		family:    "RSASSA-PKCS1",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.10040.4.3": {
		name:      "DSA-SHA-1",
		family:    "DSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"2.16.840.1.101.3.4.3.2": {
		name:      "DSA-SHA-256",
		family:    "DSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.10045.4.1": {
		name:      "ECDSA-SHA-1",
		family:    "ECDSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.10045.4.3.2": {
		name:      "ECDSA-SHA-256",
		family:    "ECDSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.10045.4.3.3": {
		name:      "ECDSA-SHA-384",
		family:    "ECDSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
	"1.2.840.10045.4.3.4": {
		name:      "ECDSA-SHA-512",
		family:    "ECDSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},

	// Subject public key algorithms.
	"1.2.840.113549.1.1.1": {
		name:      "RSA",
		primitive: ftypes.CryptoPrimitiveUnknown,
		parameter: ftypes.CryptoParameterKeySize,
	},
	"1.2.840.10045.2.1": {
		name:      "EC",
		primitive: ftypes.CryptoPrimitiveUnknown,
		parameter: ftypes.CryptoParameterCurve,
	},
	"1.2.840.10040.4.1": {
		name:      "DSA",
		family:    "DSA",
		primitive: ftypes.CryptoPrimitiveSignature,
		parameter: ftypes.CryptoParameterKeySize,
	},

	// Ed25519 uses one OID as both the key and the signature algorithm, and the curve
	// fixes its parameters.
	"1.3.101.112": {
		name:      "Ed25519",
		family:    "EdDSA",
		primitive: ftypes.CryptoPrimitiveSignature,
	},
}
