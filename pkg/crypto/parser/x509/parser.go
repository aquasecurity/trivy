package x509

import (
	"context"
	stdcrypto "crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"iter"
	"math/big"
	"slices"

	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

// objectKind identifies the kind of parsed cryptographic object.
type objectKind uint8

const (
	// objectCertificate identifies an X.509 certificate.
	objectCertificate objectKind = iota + 1
	// objectPrivateKey identifies a private key projected to its public key.
	objectPrivateKey
	// objectPublicKey identifies a public key.
	objectPublicKey
	// objectEncryptedPrivateKey identifies an opaque encrypted private key.
	objectEncryptedPrivateKey
)

// encryptionFormat identifies the container format of an encrypted private key.
type encryptionFormat uint8

const (
	// encryptionFormatPKCS8 identifies an encrypted PKCS#8 container.
	encryptionFormatPKCS8 encryptionFormat = iota + 1
	// encryptionFormatRFC1423 identifies an RFC 1423 encrypted PEM container.
	encryptionFormatRFC1423
)

// certificate is a parsed certificate together with the OID of the algorithm it is signed
// with, which crypto/x509 reports as an enumeration that does not carry it.
type certificate struct {
	*stdx509.Certificate
	signatureOID string
}

// object carries the material of a parsed cryptographic object from parsing to description.
type object struct {
	// kind identifies the parsed object kind.
	kind objectKind
	// certificate contains the parsed certificate for objectCertificate.
	certificate certificate
	// publicKey contains a public key or the public projection of a private key.
	publicKey any
	// rawPublicKey contains the SubjectPublicKeyInfo DER of a public key whose algorithm
	// crypto/x509 does not decode into a supported key.
	rawPublicKey []byte
	// encrypted contains the canonical form an encrypted private-key container is identified by.
	encrypted []byte
	// encryption identifies the encrypted private-key container format.
	encryption encryptionFormat
	// encoding identifies the source encoding.
	encoding ftypes.CryptoEncoding
	// keystore identifies the keystore the object is stored in.
	keystore ftypes.CryptoKeystoreType
	// keyFormat identifies the source key container format.
	keyFormat ftypes.CryptoKeyFormat
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

// pkcs1PrivateKey is an RSA private key in PKCS#1, as defined in RFC 8017.
type pkcs1PrivateKey struct {
	Version          int
	N                *big.Int
	E                int
	D, P, Q          *big.Int
	Dp               *big.Int               `asn1:"optional"`
	Dq               *big.Int               `asn1:"optional"`
	Qinv             *big.Int               `asn1:"optional"`
	AdditionalPrimes []pkcs1AdditionalPrime `asn1:"optional,omitempty"`
}

// pkcs1AdditionalPrime is a prime of a multi-prime RSA private key, with its CRT values.
type pkcs1AdditionalPrime struct {
	Prime, Exp, Coeff *big.Int
}

// pkcs8PrivateKey is a private key in PKCS#8, as defined in RFC 5208, without its
// optional attributes.
type pkcs8PrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

var (
	errNotCryptographic  = errors.New("not cryptographic")
	errUnsupportedCrypto = errors.New("unsupported cryptographic object")
	errMalformedCrypto   = errors.New("malformed cryptographic object")
)

// Parse describes the cryptographic material a file carries as assets, each stating
// filePath and the container it was read from.
//
// Material that cannot be read is logged and skipped. An error means a parsed object
// could not be described.
//
// An asset is reported once for each container it was found in, and an asset with no
// container of its own, such as an algorithm, once per file.
func Parse(ctx context.Context, filePath string, content []byte) ([]ftypes.CryptoAsset, error) {
	ctx = log.WithContextPrefix(ctx, "x509")
	ctx = log.WithContextAttrs(ctx, log.FilePath(filePath))
	return describe(filePath, parse(ctx, content))
}

// ParseCertificates describes DER certificates stored in the given keystore as assets. A
// certificate that cannot be read is logged and skipped, and a repeated certificate is
// reported once.
func ParseCertificates(ctx context.Context, filePath string, certificates iter.Seq[[]byte], keystore ftypes.CryptoKeystoreType) ([]ftypes.CryptoAsset, error) {
	objects := func(yield func(object) bool) {
		for der := range certificates {
			obj, err := certificateObject(der)
			if err != nil {
				logParseError(ctx, "", err)
				continue
			}
			obj.encoding = ftypes.CryptoEncodingDER
			obj.keystore = keystore
			if !yield(obj) {
				return
			}
		}
	}
	return describe(filePath, objects)
}

// describe describes objects as assets found in filePath, reporting each asset once per
// container format.
func describe(filePath string, objects iter.Seq[object]) ([]ftypes.CryptoAsset, error) {
	type assetKey struct {
		descriptor ftypes.CryptoDescriptor
		format     ftypes.CryptoKeyFormat
	}

	var assets []ftypes.CryptoAsset
	seen := set.New[assetKey]()
	for obj := range objects {
		described, err := objectToAssets(obj)
		if err != nil {
			return nil, err
		}
		for _, asset := range described {
			key := assetKey{
				descriptor: asset.Descriptor(),
				format:     asset.Format,
			}

			if seen.Contains(key) {
				continue
			}
			seen.Append(key)
			asset.FilePath = filePath
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

// parse sniffs content because eligible extensions such as .crt, .cer, and .key do not reliably identify PEM or DER.
// It decodes PEM blocks first, then falls back to DER when no valid PEM block is found.
func parse(ctx context.Context, content []byte) iter.Seq[object] {
	return func(yield func(object) bool) {
		var decodedPEM, recognized bool
		// pem.Decode scans past malformed leading data and returns the next valid block.
		for rest := content; ; {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			decodedPEM = true
			rest = next

			obj, err := parsePEMBlock(block)
			if errors.Is(err, errNotCryptographic) {
				continue
			}
			recognized = true
			if err != nil {
				logParseError(ctx, block.Type, err)
				continue
			}
			if !yield(obj) {
				return
			}
		}

		// A decoded PEM file is complete even when none of its blocks is supported.
		if decodedPEM {
			if !recognized {
				log.DebugContext(ctx, "No cryptographic object found")
			}
			return
		}

		// No PEM block was decoded, so try the whole file as DER.
		obj, err := parseDERObject(content)
		if err != nil {
			logParseError(ctx, "", err)
			return
		}
		obj.encoding = ftypes.CryptoEncodingDER
		yield(obj)
	}
}

// parsePEMBlock parses a supported PEM block and records its source encoding.
func parsePEMBlock(block *pem.Block) (object, error) {
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" || block.Headers["DEK-Info"] != "" {
		obj, err := parseRFC1423EncryptedPrivateKey(block)
		if err != nil {
			return object{}, err
		}
		obj.encoding = ftypes.CryptoEncodingPEM
		return obj, nil
	}

	obj, err := parsePEMObject(block.Type, block.Bytes)
	if err != nil {
		return object{}, err
	}

	obj.encoding = ftypes.CryptoEncodingPEM
	return obj, nil
}

// parseRFC1423EncryptedPrivateKey validates an encrypted PEM block and retains only its canonical form.
func parseRFC1423EncryptedPrivateKey(block *pem.Block) (object, error) {
	if block.Headers["Proc-Type"] != "4,ENCRYPTED" || block.Headers["DEK-Info"] == "" || len(block.Bytes) == 0 {
		return object{}, errMalformedCrypto
	}

	var keyFormat ftypes.CryptoKeyFormat
	switch block.Type {
	case "PRIVATE KEY":
		keyFormat = ftypes.CryptoKeyFormatPKCS8
	case "RSA PRIVATE KEY":
		keyFormat = ftypes.CryptoKeyFormatPKCS1
	case "EC PRIVATE KEY":
		keyFormat = ftypes.CryptoKeyFormatSEC1
	default:
		return object{}, errUnsupportedCrypto
	}

	// Re-encoding normalizes header order, line endings, and Base64 wrapping.
	encoded := pem.EncodeToMemory(block)
	if encoded == nil {
		return object{}, errMalformedCrypto
	}
	return object{
		kind:       objectEncryptedPrivateKey,
		encrypted:  encoded,
		encryption: encryptionFormatRFC1423,
		keyFormat:  keyFormat,
	}, nil
}

func parsePEMObject(label string, der []byte) (object, error) {
	switch label {
	case "CERTIFICATE":
		return certificateObject(der)
	case "PRIVATE KEY":
		return pkcs8PrivateKeyObject(der)
	case "RSA PRIVATE KEY":
		return rsaPrivateKeyObject(der, ftypes.CryptoKeyFormatPKCS1)
	case "EC PRIVATE KEY":
		return privateKeyObject(der, ftypes.CryptoKeyFormatSEC1, stdx509.ParseECPrivateKey)
	case "PUBLIC KEY":
		return publicKeyObject(der)
	case "ENCRYPTED PRIVATE KEY":
		obj, ok := parseEncryptedPKCS8(der)
		if !ok {
			return object{}, errMalformedCrypto
		}
		return obj, nil
	case "CERTIFICATE REQUEST",
		"NEW CERTIFICATE REQUEST",
		"X509 CRL",
		"OPENSSH PRIVATE KEY",
		// TODO: describe this key as well. It holds a PKCS#1 public key, which
		// x509.ParsePKCS1PublicKey reads.
		"RSA PUBLIC KEY",
		"DSA PRIVATE KEY",
		"DSA PUBLIC KEY",
		"EC PARAMETERS",
		"DH PARAMETERS",
		"DSA PARAMETERS",
		// TODO: describe this certificate as well. It holds an X.509 certificate followed
		// by the OpenSSL trust settings, so x509.ParseCertificate rejects the block as a
		// whole and only the leading certificate is readable.
		"TRUSTED CERTIFICATE",
		"PKCS7",
		"PKCS12":
		return object{}, errUnsupportedCrypto
	default:
		return object{}, errNotCryptographic
	}
}

// privateKeyObject parses a private key and projects it to its public key.
func privateKeyObject[K any](der []byte, format ftypes.CryptoKeyFormat, parseKey func([]byte) (K, error)) (object, error) {
	privateKey, err := parseKey(der)
	if err != nil {
		return object{}, errMalformedCrypto
	}
	return privateKeyToObject(privateKey, format)
}

// pkcs8PrivateKeyObject parses a private key in PKCS#8 and projects it to its public key.
func pkcs8PrivateKeyObject(der []byte) (object, error) {
	var key pkcs8PrivateKey
	if _, err := asn1.Unmarshal(der, &key); err == nil && key.Algo.Algorithm.Equal(oidRSAEncryption) {
		return rsaPrivateKeyObject(key.PrivateKey, ftypes.CryptoKeyFormatPKCS8)
	}
	return privateKeyObject(der, ftypes.CryptoKeyFormatPKCS8, stdx509.ParsePKCS8PrivateKey)
}

// rsaPrivateKeyObject reads an RSA private key in PKCS#1 and projects it to its public key.
// It checks the structure of the key but not its math, because crypto/x509 validates a key
// with arithmetic whose cost grows with the size of its values, and a crafted key picks
// them freely.
func rsaPrivateKeyObject(der []byte, format ftypes.CryptoKeyFormat) (object, error) {
	var key pkcs1PrivateKey
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil || len(rest) > 0 {
		return object{}, errMalformedCrypto
	}
	if key.Version < 0 || key.Version > 1 || key.E <= 0 {
		return object{}, errMalformedCrypto
	}
	for _, v := range []*big.Int{key.N, key.D, key.P, key.Q} {
		if v.Sign() <= 0 {
			return object{}, errMalformedCrypto
		}
	}
	for _, v := range []*big.Int{key.Dp, key.Dq, key.Qinv} {
		if v != nil && v.Sign() <= 0 {
			return object{}, errMalformedCrypto
		}
	}
	for _, p := range key.AdditionalPrimes {
		if p.Prime.Sign() <= 0 {
			return object{}, errMalformedCrypto
		}
	}

	return object{
		kind:      objectPrivateKey,
		publicKey: &rsa.PublicKey{N: key.N, E: key.E},
		keyFormat: format,
	}, nil
}

func parseDERObject(der []byte) (object, error) {
	// The target ASN.1 DER structures have no common outer discriminator, so try their schema-specific parsers in order.
	if obj, err := certificateObject(der); err == nil {
		return obj, nil
	}

	if obj, err := rsaPrivateKeyObject(der, ftypes.CryptoKeyFormatPKCS1); err == nil {
		return obj, nil
	}

	if obj, err := pkcs8PrivateKeyObject(der); !errors.Is(err, errMalformedCrypto) {
		return obj, err
	}

	if privateKey, err := stdx509.ParseECPrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatSEC1)
	}

	if obj, err := publicKeyObject(der); err == nil {
		return obj, nil
	}

	if obj, ok := parseEncryptedPKCS8(der); ok {
		return obj, nil
	}

	if _, err := stdx509.ParseCertificateRequest(der); err == nil {
		return object{}, errUnsupportedCrypto
	}
	if _, err := stdx509.ParseRevocationList(der); err == nil {
		return object{}, errUnsupportedCrypto
	}

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err == nil && len(rest) == 0 && raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence && raw.IsCompound {
		return object{}, errUnsupportedCrypto
	}
	if len(der) > 0 && der[0] == byte(asn1.TagSequence)|0x20 {
		return object{}, errMalformedCrypto
	}
	return object{}, errNotCryptographic
}

// certificateObject parses a certificate and reads the OID of its signature algorithm out
// of the encoded algorithm identifier.
func certificateObject(der []byte) (object, error) {
	parsed, err := stdx509.ParseCertificate(der)
	if err != nil {
		return object{}, errMalformedCrypto
	}

	// The OID is read from the encoding because crypto/x509 reports the algorithm as an
	// enumeration, and an algorithm it does not recognize collapses into a single unknown
	// value.
	var signature pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(parsed.RawSignatureAlgorithm, &signature); err != nil {
		return object{}, errMalformedCrypto
	}

	// crypto/x509 checks the encoding only of a key it decodes, and any other key is
	// described from its encoding later.
	if !isSupportedPublicKey(parsed.PublicKey) {
		if _, err := crypto.ParseSubjectPublicKeyInfo(parsed.RawSubjectPublicKeyInfo); err != nil {
			return object{}, errMalformedCrypto
		}
	}

	return object{
		kind: objectCertificate,
		certificate: certificate{
			Certificate:  parsed,
			signatureOID: signature.Algorithm.String(),
		},
	}, nil
}

// privateKeyToObject converts a private key to an object containing its public projection.
func privateKeyToObject(privateKey any, format ftypes.CryptoKeyFormat) (object, error) {
	signer, ok := privateKey.(stdcrypto.Signer)
	if !ok {
		return object{}, errUnsupportedCrypto
	}
	publicKey := signer.Public()
	if !isSupportedPublicKey(publicKey) {
		return object{}, errUnsupportedCrypto
	}
	return object{
		kind:      objectPrivateKey,
		publicKey: publicKey,
		keyFormat: format,
	}, nil
}

// decodedKeyAlgorithms lists the key algorithms crypto/x509 decodes. It mirrors
// parsePublicKey in crypto/x509 and needs updating when that function learns a new OID.
var decodedKeyAlgorithms = []asn1.ObjectIdentifier{
	oidRSAEncryption,
	{1, 2, 840, 10040, 4, 1},          // DSA
	{1, 2, 840, 10045, 2, 1},          // EC
	{1, 3, 101, 110},                  // X25519
	{1, 3, 101, 112},                  // Ed25519
	{2, 16, 840, 1, 101, 3, 4, 3, 17}, // ML-DSA-44
	{2, 16, 840, 1, 101, 3, 4, 3, 18}, // ML-DSA-65
	{2, 16, 840, 1, 101, 3, 4, 3, 19}, // ML-DSA-87
}

// publicKeyObject parses a public key in PKIX SubjectPublicKeyInfo. A key crypto/x509 does
// not decode into a supported key is kept in its encoded form, the same way as in a
// certificate. A key of an algorithm it decodes is malformed when decoding fails.
func publicKeyObject(der []byte) (object, error) {
	publicKey, parseErr := stdx509.ParsePKIXPublicKey(der)
	if parseErr == nil && isSupportedPublicKey(publicKey) {
		return object{
			kind:      objectPublicKey,
			publicKey: publicKey,
			keyFormat: ftypes.CryptoKeyFormatPKIX,
		}, nil
	}

	oid, err := crypto.ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return object{}, errMalformedCrypto
	}
	// A key of an algorithm crypto/x509 decodes is malformed only when decoding failed. An
	// X25519 key decodes into a key that is not supported and is kept in its encoded form.
	if parseErr != nil && slices.ContainsFunc(decodedKeyAlgorithms, oid.Equal) {
		return object{}, errMalformedCrypto
	}
	return object{
		kind:         objectPublicKey,
		rawPublicKey: der,
		keyFormat:    ftypes.CryptoKeyFormatPKIX,
	}, nil
}

// parseEncryptedPKCS8 validates only the opaque envelope and retains the DER it was read from.
func parseEncryptedPKCS8(der []byte) (object, bool) {
	var encrypted encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &encrypted)
	if err != nil || len(rest) != 0 || len(encrypted.Algorithm.Algorithm) == 0 || len(encrypted.EncryptedData) == 0 {
		return object{}, false
	}
	return object{
		kind:       objectEncryptedPrivateKey,
		encrypted:  der,
		encryption: encryptionFormatPKCS8,
		keyFormat:  ftypes.CryptoKeyFormatPKCS8,
	}, true
}

func isSupportedPublicKey(key any) bool {
	switch key.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *mldsa.PublicKey:
		return true
	default:
		return false
	}
}

func logParseError(ctx context.Context, pemType string, err error) {
	var attrs []any
	if pemType != "" {
		attrs = append(attrs, log.String("pem_type", pemType))
	}

	switch {
	case errors.Is(err, errUnsupportedCrypto):
		log.DebugContext(ctx, "Unsupported cryptographic object", attrs...)
	case errors.Is(err, errMalformedCrypto):
		log.WarnContext(ctx, "Malformed cryptographic object", attrs...)
	default:
		log.DebugContext(ctx, "No cryptographic object found", attrs...)
	}
}
