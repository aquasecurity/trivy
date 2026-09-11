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

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
	// encrypted contains the canonical form an encrypted private-key container is identified by.
	encrypted []byte
	// encryption identifies the encrypted private-key container format.
	encryption encryptionFormat
	// encoding identifies the source encoding.
	encoding ftypes.CryptoEncoding
	// keyFormat identifies the source key container format.
	keyFormat ftypes.CryptoKeyFormat
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

var (
	errNotCryptographic  = errors.New("not cryptographic")
	errUnsupportedCrypto = errors.New("unsupported cryptographic object")
	errMalformedCrypto   = errors.New("malformed cryptographic object")
)

// Parse describes the cryptographic material a file carries as assets.
//
// Material that cannot be read is logged and skipped. An error means the description
// itself failed, which is a bug here rather than a problem with the input, and the assets
// described before it are returned along with it.
func Parse(ctx context.Context, filePath string, content []byte) ([]ftypes.CryptoAssetInfo, error) {
	ctx = log.WithContextPrefix(ctx, "x509")
	ctx = log.WithContextAttrs(ctx, log.FilePath(filePath))

	var assets []ftypes.CryptoAssetInfo
	for _, obj := range parse(ctx, content) {
		described, err := objectToAssets(ctx, obj)
		if err != nil {
			return assets, err
		}
		assets = append(assets, described...)
	}
	return assets, nil
}

// parse sniffs content because eligible extensions such as .crt, .cer, and .key do not reliably identify PEM or DER.
// It decodes PEM blocks first, then falls back to DER when no valid PEM block is found.
func parse(ctx context.Context, content []byte) []object {
	var objects []object
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
		objects = append(objects, obj)
	}

	// A decoded PEM file is complete even when none of its blocks is supported.
	if decodedPEM {
		if !recognized {
			log.DebugContext(ctx, "No cryptographic object found")
		}
		return objects
	}

	// No PEM block was decoded, so try the whole file as DER.
	obj, err := parseDERObject(content)
	if err != nil {
		logParseError(ctx, "", err)
		return nil
	}
	obj.encoding = ftypes.CryptoEncodingDER
	return []object{obj}
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
		privateKey, err := stdx509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return object{}, errMalformedCrypto
		}
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatPKCS8)
	case "RSA PRIVATE KEY":
		privateKey, err := stdx509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return object{}, errMalformedCrypto
		}
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatPKCS1)
	case "EC PRIVATE KEY":
		privateKey, err := stdx509.ParseECPrivateKey(der)
		if err != nil {
			return object{}, errMalformedCrypto
		}
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatSEC1)
	case "PUBLIC KEY":
		publicKey, err := stdx509.ParsePKIXPublicKey(der)
		if err != nil {
			return object{}, errMalformedCrypto
		}
		return publicKeyToObject(publicKey)
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

func parseDERObject(der []byte) (object, error) {
	// The target ASN.1 DER structures have no common outer discriminator, so try their schema-specific parsers in order.
	if obj, err := certificateObject(der); err == nil {
		return obj, nil
	}

	if privateKey, err := stdx509.ParsePKCS1PrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatPKCS1)
	}

	if privateKey, err := stdx509.ParsePKCS8PrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatPKCS8)
	}

	if privateKey, err := stdx509.ParseECPrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, ftypes.CryptoKeyFormatSEC1)
	}

	if publicKey, err := stdx509.ParsePKIXPublicKey(der); err == nil {
		return publicKeyToObject(publicKey)
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
// of the same bytes.
func certificateObject(der []byte) (object, error) {
	parsed, err := stdx509.ParseCertificate(der)
	if err != nil {
		return object{}, errMalformedCrypto
	}

	oid, ok := signatureAlgorithmOID(parsed.Raw)
	if !ok {
		return object{}, errMalformedCrypto
	}

	return object{
		kind: objectCertificate,
		certificate: certificate{
			Certificate:  parsed,
			signatureOID: oid,
		},
	}, nil
}

// signatureAlgorithmOID reads the signature algorithm OID out of certificate DER. The OID
// is read from the encoding because crypto/x509 reports the algorithm as an enumeration,
// and an algorithm it does not recognize collapses into a single unknown value.
func signatureAlgorithmOID(der []byte) (string, bool) {
	// The signed part is consumed as a raw value only to reach the algorithm that follows
	// it. The signature value after the algorithm is left out, because encoding/asn1
	// tolerates elements of a sequence that the target struct does not declare.
	var parsed struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return "", false
	}
	return parsed.SignatureAlgorithm.Algorithm.String(), true
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

func publicKeyToObject(publicKey any) (object, error) {
	if !isSupportedPublicKey(publicKey) {
		return object{}, errUnsupportedCrypto
	}
	return object{
		kind:      objectPublicKey,
		publicKey: publicKey,
		keyFormat: ftypes.CryptoKeyFormatPKIX,
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
