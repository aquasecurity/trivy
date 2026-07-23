package x509

import (
	"context"
	stdcrypto "crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"

	cryptotypes "github.com/aquasecurity/trivy/pkg/crypto"
	"github.com/aquasecurity/trivy/pkg/log"
)

// ObjectKind identifies the kind of parsed cryptographic object.
type ObjectKind uint8

const (
	// ObjectCertificate identifies an X.509 certificate.
	ObjectCertificate ObjectKind = iota + 1
	// ObjectPrivateKey identifies a private key projected to its public key.
	ObjectPrivateKey
	// ObjectPublicKey identifies a public key.
	ObjectPublicKey
	// ObjectEncryptedPrivateKey identifies an opaque encrypted PKCS#8 private key.
	ObjectEncryptedPrivateKey
)

// Object is a safe projection of a parsed cryptographic object.
type Object struct {
	// Kind identifies the parsed object kind.
	Kind ObjectKind
	// Certificate contains the parsed certificate for ObjectCertificate.
	Certificate *stdx509.Certificate
	// PublicKey contains a public key or the public projection of a private key.
	PublicKey any
	// EncryptedPKCS8SHA256 contains the lowercase SHA-256 digest of an encrypted PKCS#8 container.
	EncryptedPKCS8SHA256 string
	// Encoding identifies the source encoding.
	Encoding cryptotypes.Encoding
	// KeyFormat identifies the source key container format.
	KeyFormat cryptotypes.KeyFormat
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

// Parse sniffs content because eligible extensions such as .crt, .cer, and .key do not reliably identify PEM or DER.
// It decodes PEM blocks first, then falls back to DER when no valid PEM block is found.
func Parse(ctx context.Context, filePath string, content []byte) []Object {
	ctx = log.WithContextPrefix(ctx, "x509")
	var objects []Object
	var decodedPEM, recognized bool
	// pem.Decode scans past malformed leading data and returns the next valid block.
	for rest := content; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		decodedPEM = true
		rest = next

		object, err := parsePEMBlock(block)
		if errors.Is(err, errNotCryptographic) {
			continue
		}
		recognized = true
		if err != nil {
			logParseError(ctx, filePath, block.Type, err)
			continue
		}
		objects = append(objects, object)
	}

	// A decoded PEM file is complete even when none of its blocks is supported.
	if decodedPEM {
		if !recognized {
			log.DebugContext(ctx, "No cryptographic object found", log.FilePath(filePath))
		}
		return objects
	}

	// No PEM block was decoded, so try the whole file as DER.
	object, err := parseDERObject(content)
	if err != nil {
		logParseError(ctx, filePath, "", err)
		return nil
	}
	return []Object{object}
}

func parsePEMBlock(block *pem.Block) (Object, error) {
	object, err := parsePEMObject(block.Type, block.Bytes)
	if err != nil {
		return Object{}, err
	}

	object.Encoding = cryptotypes.EncodingPEM
	return object, nil
}

func parsePEMObject(label string, der []byte) (Object, error) {
	switch label {
	case "CERTIFICATE":
		certificate, err := stdx509.ParseCertificate(der)
		if err != nil {
			return Object{}, errMalformedCrypto
		}
		return Object{
			Kind:        ObjectCertificate,
			Certificate: certificate,
			Encoding:    cryptotypes.EncodingDER,
		}, nil
	case "PRIVATE KEY":
		privateKey, err := stdx509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return Object{}, errMalformedCrypto
		}
		return privateKeyToObject(privateKey, cryptotypes.KeyFormatPKCS8)
	case "RSA PRIVATE KEY":
		privateKey, err := stdx509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return Object{}, errMalformedCrypto
		}
		return privateKeyToObject(privateKey, cryptotypes.KeyFormatPKCS1)
	case "EC PRIVATE KEY":
		privateKey, err := stdx509.ParseECPrivateKey(der)
		if err != nil {
			return Object{}, errMalformedCrypto
		}
		return privateKeyToObject(privateKey, cryptotypes.KeyFormatSEC1)
	case "PUBLIC KEY":
		publicKey, err := stdx509.ParsePKIXPublicKey(der)
		if err != nil {
			return Object{}, errMalformedCrypto
		}
		return publicKeyToObject(publicKey)
	case "ENCRYPTED PRIVATE KEY":
		object, ok := parseEncryptedPKCS8(der)
		if !ok {
			return Object{}, errMalformedCrypto
		}
		return object, nil
	case "CERTIFICATE REQUEST",
		"NEW CERTIFICATE REQUEST",
		"X509 CRL",
		"OPENSSH PRIVATE KEY",
		"RSA PUBLIC KEY",
		"DSA PRIVATE KEY",
		"DSA PUBLIC KEY",
		"EC PARAMETERS",
		"DH PARAMETERS",
		"TRUSTED CERTIFICATE",
		"PKCS7",
		"PKCS12":
		return Object{}, errUnsupportedCrypto
	default:
		return Object{}, errNotCryptographic
	}
}

func parseDERObject(der []byte) (Object, error) {
	// The target ASN.1 DER structures have no common outer discriminator, so try their schema-specific parsers in order.
	if certificate, err := stdx509.ParseCertificate(der); err == nil {
		return Object{
			Kind:        ObjectCertificate,
			Certificate: certificate,
			Encoding:    cryptotypes.EncodingDER,
		}, nil
	}

	if privateKey, err := stdx509.ParsePKCS1PrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, cryptotypes.KeyFormatPKCS1)
	}

	if privateKey, err := stdx509.ParsePKCS8PrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, cryptotypes.KeyFormatPKCS8)
	}

	if privateKey, err := stdx509.ParseECPrivateKey(der); err == nil {
		return privateKeyToObject(privateKey, cryptotypes.KeyFormatSEC1)
	}

	if publicKey, err := stdx509.ParsePKIXPublicKey(der); err == nil {
		return publicKeyToObject(publicKey)
	}

	if object, ok := parseEncryptedPKCS8(der); ok {
		return object, nil
	}

	if _, err := stdx509.ParseCertificateRequest(der); err == nil {
		return Object{}, errUnsupportedCrypto
	}
	if _, err := stdx509.ParseRevocationList(der); err == nil {
		return Object{}, errUnsupportedCrypto
	}

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err == nil && len(rest) == 0 && raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence && raw.IsCompound {
		return Object{}, errUnsupportedCrypto
	}
	if len(der) > 0 && der[0] == byte(asn1.TagSequence)|0x20 {
		return Object{}, errMalformedCrypto
	}
	return Object{}, errNotCryptographic
}

// privateKeyToObject converts a private key to an Object containing its public projection.
func privateKeyToObject(privateKey any, format cryptotypes.KeyFormat) (Object, error) {
	signer, ok := privateKey.(stdcrypto.Signer)
	if !ok {
		return Object{}, errUnsupportedCrypto
	}
	publicKey := signer.Public()
	if !isSupportedPublicKey(publicKey) {
		return Object{}, errUnsupportedCrypto
	}
	return Object{
		Kind:      ObjectPrivateKey,
		PublicKey: publicKey,
		Encoding:  cryptotypes.EncodingDER,
		KeyFormat: format,
	}, nil
}

func publicKeyToObject(publicKey any) (Object, error) {
	if !isSupportedPublicKey(publicKey) {
		return Object{}, errUnsupportedCrypto
	}
	return Object{
		Kind:      ObjectPublicKey,
		PublicKey: publicKey,
		Encoding:  cryptotypes.EncodingDER,
		KeyFormat: cryptotypes.KeyFormatPKIX,
	}, nil
}

// parseEncryptedPKCS8 validates only the opaque envelope and retains its digest.
func parseEncryptedPKCS8(der []byte) (Object, bool) {
	var encrypted encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &encrypted)
	if err != nil || len(rest) != 0 || len(encrypted.Algorithm.Algorithm) == 0 || len(encrypted.EncryptedData) == 0 {
		return Object{}, false
	}
	digest := sha256.Sum256(der)
	return Object{
		Kind:                 ObjectEncryptedPrivateKey,
		EncryptedPKCS8SHA256: hex.EncodeToString(digest[:]),
		Encoding:             cryptotypes.EncodingDER,
		KeyFormat:            cryptotypes.KeyFormatPKCS8,
	}, true
}

func isSupportedPublicKey(key any) bool {
	switch key.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

func logParseError(ctx context.Context, filePath, pemType string, err error) {
	logger := log.With(log.FilePath(filePath))
	if pemType != "" {
		logger = logger.With(log.String("pem_type", pemType))
	}

	switch {
	case errors.Is(err, errUnsupportedCrypto):
		logger.InfoContext(ctx, "Unsupported cryptographic object")
	case errors.Is(err, errMalformedCrypto):
		logger.WarnContext(ctx, "Malformed cryptographic object")
	default:
		logger.DebugContext(ctx, "No cryptographic object found")
	}
}
