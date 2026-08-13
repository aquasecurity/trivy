package crypto

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"strconv"

	"golang.org/x/xerrors"

	cryptox509 "github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

// Extract describes a parsed cryptographic object as assets. It returns nil for an
// object it cannot describe, such as a key with no canonical form. FilePath and Layer
// are left to the caller.
func Extract(object cryptox509.Object) []ftypes.CryptoAsset {
	switch object.Kind {
	case cryptox509.ObjectCertificate:
		return extractCertificate(object.Certificate, object.Encoding)
	case cryptox509.ObjectPublicKey:
		return extractKey(object.KeyFormat, object.Encoding, ftypes.CryptoKeyTypePublic, object.PublicKey)
	case cryptox509.ObjectPrivateKey:
		return extractKey(object.KeyFormat, object.Encoding, ftypes.CryptoKeyTypePrivate, object.PublicKey)
	case cryptox509.ObjectEncryptedPrivateKey:
		return extractEncryptedPrivateKey(object.KeyFormat, object.Encoding, object.EncryptedPKCS8SHA256)
	default:
		return nil
	}
}

// extractCertificate describes a certificate, the algorithm it is signed with, the key
// it carries and the algorithm of that key. An algorithm or a key that cannot be
// described is left out, and the certificate keeps the relationships it can state.
func extractCertificate(cert *x509.Certificate, encoding ftypes.CryptoEncoding) []ftypes.CryptoAsset {
	digest := sha256.Sum256(cert.Raw)

	certificate := ftypes.CryptoAsset{
		Kind: ftypes.CryptoKindCertificate,
		Identity: ftypes.CryptoIdentity{
			Method: ftypes.CryptoMethodSHA256,
			Value:  hex.EncodeToString(digest[:]),
		},
		Name: certificateName(cert),

		Certificate: &ftypes.CryptoCertificate{
			// The full distinguished name is reported, because a certificate authority
			// often identifies itself by organization alone and carries no common name.
			Subject:          cert.Subject.String(),
			Issuer:           cert.Issuer.String(),
			SerialNumber:     cert.SerialNumber.Text(16),
			NotBefore:        cert.NotBefore,
			NotAfter:         cert.NotAfter,
			Format:           ftypes.CryptoCertificateFormatX509,
			Encoding:         encoding,
			KeyUsage:         keyUsages(cert.KeyUsage),
			ExtendedKeyUsage: extendedKeyUsages(cert),
			DNSNames:         cert.DNSNames,
			EmailAddresses:   cert.EmailAddresses,
			IPAddresses: xslices.Map(cert.IPAddresses, func(ip net.IP) string {
				return ip.String()
			}),
			URIs: xslices.Map(cert.URIs, func(u *url.URL) string {
				return u.String()
			}),
			BasicConstraintsValid: cert.BasicConstraintsValid,
			IsCA:                  cert.IsCA,
			// crypto/x509 reports -1 when basic constraints carry no path length,
			// which this model represents as an unset zero.
			MaxPathLen:     max(cert.MaxPathLen, 0),
			MaxPathLenZero: cert.MaxPathLenZero,
		},
	}

	// A signature algorithm gets no key parameters, because the key that produced the
	// signature belongs to the issuer, and this certificate stores the key of its subject.
	signature := algorithmAsset(signatureAlgorithmOID(cert), 0, "")
	certificate.Relationships = append(certificate.Relationships, ftypes.CryptoRelationship{
		Type:         ftypes.CryptoRelationshipSignedWith,
		RelatedAsset: signature.Descriptor(),
	})
	related := []ftypes.CryptoAsset{signature}

	// The key stays without a format and an encoding, because it is not a standalone
	// container.
	if key, keyAlgorithm, ok := describeKey("", "", ftypes.CryptoKeyTypePublic, cert.PublicKey); ok {
		certificate.Relationships = append(certificate.Relationships, ftypes.CryptoRelationship{
			Type:         ftypes.CryptoRelationshipContains,
			RelatedAsset: key.Descriptor(),
		})
		related = append(related, key, keyAlgorithm)
	}

	return append([]ftypes.CryptoAsset{certificate}, related...)
}

// certificateName prefers the common name and falls back to the full distinguished
// name, which is the only subject identifier some certificates carry.
func certificateName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

// keyUsageBits lists every RFC 5280 key usage bit. The order is fixed so that a
// certificate always reports its usages in the same order.
var keyUsageBits = []x509.KeyUsage{
	x509.KeyUsageDigitalSignature,
	x509.KeyUsageContentCommitment,
	x509.KeyUsageKeyEncipherment,
	x509.KeyUsageDataEncipherment,
	x509.KeyUsageKeyAgreement,
	x509.KeyUsageCertSign,
	x509.KeyUsageCRLSign,
	x509.KeyUsageEncipherOnly,
	x509.KeyUsageDecipherOnly,
}

// keyUsages names the bits set in usage. Each bit is named on its own because a
// combined mask is not a named constant.
func keyUsages(usage x509.KeyUsage) []string {
	var usages []string
	for _, bit := range keyUsageBits {
		if usage&bit != 0 {
			usages = append(usages, bit.String())
		}
	}
	return usages
}

// extendedKeyUsages reports recognized usages by name and the rest by OID, because a
// usage defined outside RFC 5280 has no name to report.
func extendedKeyUsages(cert *x509.Certificate) []string {
	usages := xslices.Map(cert.ExtKeyUsage, func(usage x509.ExtKeyUsage) string {
		return usage.String()
	})
	unknown := xslices.Map(cert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) string {
		return oid.String()
	})
	return append(usages, unknown...)
}

// extractKey describes a standalone key object as the key itself and the algorithm it
// belongs to.
func extractKey(
	format ftypes.CryptoKeyFormat,
	encoding ftypes.CryptoEncoding,
	keyType ftypes.CryptoKeyType,
	pub any,
) []ftypes.CryptoAsset {
	key, keyAlgorithm, ok := describeKey(format, encoding, keyType, pub)
	if !ok {
		return nil
	}
	return []ftypes.CryptoAsset{key, keyAlgorithm}
}

// describeKey describes a key and the algorithm it belongs to. An Object always carries
// the public projection, so a private key differs from a public one only in its key
// type. The format and the encoding are empty for a key derived from an enclosing
// object, such as a certificate. It reports false for a key with no canonical form.
func describeKey(
	format ftypes.CryptoKeyFormat,
	encoding ftypes.CryptoEncoding,
	keyType ftypes.CryptoKeyType,
	pub any,
) (ftypes.CryptoAsset, ftypes.CryptoAsset, bool) {
	identity, oid, ok := publicKeyInfo(pub)
	if !ok {
		return ftypes.CryptoAsset{}, ftypes.CryptoAsset{}, false
	}

	size, curve := keyDetails(pub)
	keyAlgorithm := algorithmAsset(oid, size, curve)

	key := ftypes.CryptoAsset{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  keyType,
		Identity: identity,
		Name:     keyAlgorithm.Name + " " + string(keyType) + " key",

		Key: &ftypes.CryptoKey{
			Size:     size,
			Curve:    curve,
			Format:   format,
			Encoding: encoding,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: keyAlgorithm.Descriptor(),
		}},
	}
	return key, keyAlgorithm, true
}

// keyDetails reports the size in bits and the curve of a public key.
func keyDetails(pub any) (int, string) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen(), ""
	case *dsa.PublicKey:
		return pub.P.BitLen(), ""
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize, pub.Curve.Params().Name
	case ed25519.PublicKey:
		// An Ed25519 key is the raw point, so its length is the key size in bytes.
		return len(pub) * 8, ""
	}
	return 0, ""
}

// algorithmAsset describes the algorithm an OID identifies. The size and the curve
// belong to the key the algorithm is used with and are zero for a signature algorithm.
func algorithmAsset(oid string, size int, curve string) ftypes.CryptoAsset {
	found, known := algorithms[oid]
	if !known {
		// An unrecognized OID is still reported, named by the OID itself.
		return ftypes.CryptoAsset{
			Kind: ftypes.CryptoKindAlgorithm,
			Identity: ftypes.CryptoIdentity{
				Method: ftypes.CryptoMethodOID,
				Value:  oid,
			},
			Name: oid,

			Algorithm: &ftypes.CryptoAlgorithm{
				Primitive: ftypes.CryptoPrimitiveUnknown,
			},
		}
	}

	name := found.name
	var parameters string
	switch {
	case found.parameter == ftypes.CryptoParameterKeySize && size > 0:
		value := strconv.Itoa(size)
		name += "-" + value
		parameters = string(ftypes.CryptoParameterKeySize) + "=" + value
	case found.parameter == ftypes.CryptoParameterCurve && curve != "":
		name += "-" + curve
		parameters = string(ftypes.CryptoParameterCurve) + "=" + curve
	}

	return ftypes.CryptoAsset{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      oid,
			Parameters: parameters,
		},
		Name: name,

		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    found.family,
			Primitive: found.primitive,
		},
	}
}

// publicKeyInfo canonicalizes a key as PKIX SubjectPublicKeyInfo and reports the digest
// identifying it together with the OID of its algorithm. It reports false for a key of an
// algorithm that cannot be encoded, and for the absent key of a certificate whose
// algorithm crypto/x509 does not recognize.
func publicKeyInfo(pub any) (ftypes.CryptoIdentity, string, bool) {
	der, err := marshalPublicKey(pub)
	if err != nil {
		return ftypes.CryptoIdentity{}, "", false
	}

	digest := sha256.Sum256(der)
	identity := ftypes.CryptoIdentity{
		Method: ftypes.CryptoMethodSPKISHA256,
		Value:  hex.EncodeToString(digest[:]),
	}
	return identity, subjectPublicKeyOID(der), true
}

// oidDSA identifies a DSA public key, defined by RFC 3279 section 2.3.2.
// See https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2
var oidDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}

// marshalPublicKey encodes a public key as PKIX SubjectPublicKeyInfo.
func marshalPublicKey(pub any) ([]byte, error) {
	if key, ok := pub.(*dsa.PublicKey); ok {
		return marshalDSAPublicKey(key)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// marshalDSAPublicKey encodes a DSA public key the way RFC 3279 section 2.3.2 defines it:
// the domain parameters travel in the algorithm identifier, and the public value is a
// DER integer inside the bit string. crypto/x509 parses this form but cannot produce it.
// See https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2
func marshalDSAPublicKey(pub *dsa.PublicKey) ([]byte, error) {
	parameters, err := asn1.Marshal(struct {
		P, Q, G *big.Int
	}{pub.P, pub.Q, pub.G})
	if err != nil {
		return nil, xerrors.Errorf("marshal DSA parameters: %w", err)
	}

	value, err := asn1.Marshal(pub.Y)
	if err != nil {
		return nil, xerrors.Errorf("marshal DSA public value: %w", err)
	}

	der, err := asn1.Marshal(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidDSA,
			Parameters: asn1.RawValue{FullBytes: parameters},
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     value,
			BitLength: len(value) * 8,
		},
	})
	if err != nil {
		return nil, xerrors.Errorf("marshal DSA subject public key info: %w", err)
	}
	return der, nil
}

// subjectPublicKeyOID reads the algorithm OID out of SubjectPublicKeyInfo DER. The OID
// is read from the encoding rather than from PublicKeyAlgorithm, which is an enumeration
// that does not carry it.
//
// The result is empty only when the DER does not parse, which cannot happen for the
// output of MarshalPKIXPublicKey.
func subjectPublicKeyOID(der []byte) string {
	// The key itself follows the algorithm and is left unread, because encoding/asn1
	// tolerates elements of a sequence that the target struct does not declare.
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return ""
	}
	return info.Algorithm.Algorithm.String()
}

// signatureAlgorithmOID reads the signature algorithm OID out of the certificate DER,
// because crypto/x509 reports the algorithm as an enumeration that does not carry the OID.
//
// The result is empty only when the certificate DER does not parse, which cannot happen
// for a certificate crypto/x509 has already parsed.
func signatureAlgorithmOID(cert *x509.Certificate) string {
	// The signed part is consumed as a raw value only to reach the algorithm that follows
	// it. The signature value after the algorithm is left out, because encoding/asn1
	// tolerates elements of a sequence that the target struct does not declare.
	var certificate struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(cert.Raw, &certificate); err != nil {
		return ""
	}
	return certificate.SignatureAlgorithm.Algorithm.String()
}

// extractEncryptedPrivateKey describes an encrypted PKCS#8 container. Its algorithm,
// size and curve live inside the encrypted payload and stay unset.
func extractEncryptedPrivateKey(
	format ftypes.CryptoKeyFormat,
	encoding ftypes.CryptoEncoding,
	digest string,
) []ftypes.CryptoAsset {
	return []ftypes.CryptoAsset{
		{
			Kind:    ftypes.CryptoKindKey,
			KeyType: ftypes.CryptoKeyTypePrivate,
			Identity: ftypes.CryptoIdentity{
				Method: ftypes.CryptoMethodEncryptedPKCS8SHA256,
				Value:  digest,
			},
			// The container states its format, and nothing else about the key is
			// readable without the passphrase.
			Name: "Encrypted " + string(format) + " private key",

			Key: &ftypes.CryptoKey{
				Format:    format,
				Encoding:  encoding,
				Encrypted: true,
			},
		},
	}
}
