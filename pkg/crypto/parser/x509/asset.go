package x509

import (
	"cmp"
	stdx509 "crypto/x509"
	"encoding/asn1"
	"net"
	"net/url"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

// objectToAssets describes a parsed object as assets. An error means the description itself
// is broken.
func objectToAssets(obj object) ([]ftypes.CryptoAsset, error) {
	switch obj.kind {
	case objectCertificate:
		return describeCertificate(obj.certificate, obj.encoding, obj.keystore)
	case objectPublicKey:
		return describeStandaloneKey(obj, ftypes.CryptoKeyTypePublic)
	case objectPrivateKey:
		return describeStandaloneKey(obj, ftypes.CryptoKeyTypePrivate)
	case objectEncryptedPrivateKey:
		return describeEncryptedPrivateKey(obj)
	default:
		return nil, xerrors.Errorf("object kind %d has no description", obj.kind)
	}
}

// describeCertificate describes a certificate, the algorithm it is signed with, the key
// it carries and the algorithm of that key.
func describeCertificate(
	cert certificate,
	encoding ftypes.CryptoEncoding,
	keystore ftypes.CryptoKeystoreType,
) ([]ftypes.CryptoAsset, error) {
	// The full distinguished name is reported, because a certificate authority often
	// identifies itself by organization alone and carries no common name.
	subject := cert.Subject.String()

	info := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindCertificate,
		Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, cert.Raw),
		Name:     cmp.Or(cert.Subject.CommonName, subject),

		Certificate: &ftypes.CryptoCertificate{
			Subject:          subject,
			Issuer:           cert.Issuer.String(),
			SerialNumber:     cert.SerialNumber.Text(16),
			NotBefore:        cert.NotBefore,
			NotAfter:         cert.NotAfter,
			Format:           ftypes.CryptoCertificateFormatX509,
			KeyUsage:         keyUsages(cert.KeyUsage),
			ExtendedKeyUsage: extendedKeyUsages(cert.Certificate),
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
			MaxPathLen:     int64(max(cert.MaxPathLen, 0)),
			MaxPathLenZero: cert.MaxPathLenZero,
		},
	}

	// A signature algorithm gets no key parameters, because the key that produced the
	// signature belongs to the issuer, and this certificate stores the key of its subject.
	signature := crypto.DescribeAlgorithm(cert.signatureOID, 0, 0, "")
	info.Relationships = append(info.Relationships, ftypes.CryptoRelationship{
		Type:         ftypes.CryptoRelationshipSignedWith,
		RelatedAsset: signature.Descriptor(),
	})
	// Nothing a certificate carries has a container of its own.
	related := []ftypes.CryptoAsset{{CryptoAssetInfo: signature}}

	key, keyAlgorithm, err := describeKey(cert.PublicKey, cert.RawSubjectPublicKeyInfo, ftypes.CryptoKeyTypePublic)
	if err != nil {
		return nil, xerrors.Errorf("describe certificate key: %w", err)
	}
	info.Relationships = append(info.Relationships, ftypes.CryptoRelationship{
		Type:         ftypes.CryptoRelationshipContains,
		RelatedAsset: key.Descriptor(),
	})
	related = append(related,
		ftypes.CryptoAsset{CryptoAssetInfo: key},
		ftypes.CryptoAsset{CryptoAssetInfo: keyAlgorithm},
	)

	asset := ftypes.CryptoAsset{
		CryptoAssetInfo: info,
		Encoding:        encoding,
		Keystore:        keystore,
	}
	return append([]ftypes.CryptoAsset{asset}, related...), nil
}

// describeKey describes a key. A key that crypto/x509 does not decode into a supported key
// is described from its SubjectPublicKeyInfo.
func describeKey(pub any, spki []byte, keyType ftypes.CryptoKeyType) (key, keyAlgorithm ftypes.CryptoAssetInfo, err error) {
	if !isSupportedPublicKey(pub) {
		return crypto.DescribeRawPublicKey(spki, keyType)
	}
	return crypto.DescribeKey(pub, keyType)
}

// describeStandaloneKey describes a key object as the key itself and the algorithm it
// belongs to.
func describeStandaloneKey(obj object, keyType ftypes.CryptoKeyType) ([]ftypes.CryptoAsset, error) {
	key, keyAlgorithm, err := describeKey(obj.publicKey, obj.rawPublicKey, keyType)
	if err != nil {
		return nil, xerrors.Errorf("describe %s key: %w", keyType, err)
	}
	return []ftypes.CryptoAsset{
		{
			CryptoAssetInfo: key,
			Format:          obj.keyFormat,
			Encoding:        obj.encoding,
		},
		// The algorithm is derived and has no encoded form.
		{CryptoAssetInfo: keyAlgorithm},
	}, nil
}

// describeEncryptedPrivateKey describes an encrypted private key container. The container
// format selects the identification method, because each method digests a different
// canonical form.
func describeEncryptedPrivateKey(obj object) ([]ftypes.CryptoAsset, error) {
	var method ftypes.CryptoIdentityMethod
	switch obj.encryption {
	case encryptionFormatPKCS8:
		method = ftypes.CryptoMethodEncryptedPKCS8SHA256
	case encryptionFormatRFC1423:
		method = ftypes.CryptoMethodEncryptedRFC1423SHA256
	default:
		return nil, xerrors.Errorf("encryption format %d has no identification method", obj.encryption)
	}

	key := crypto.DescribeEncryptedKey(method, obj.encrypted, obj.keyFormat)
	return []ftypes.CryptoAsset{{
		CryptoAssetInfo: key,
		Format:          obj.keyFormat,
		Encoding:        obj.encoding,
	}}, nil
}

// keyUsageBits lists every RFC 5280 key usage bit. The order is fixed so that a
// certificate always reports its usages in the same order.
var keyUsageBits = []stdx509.KeyUsage{
	stdx509.KeyUsageDigitalSignature,
	stdx509.KeyUsageContentCommitment,
	stdx509.KeyUsageKeyEncipherment,
	stdx509.KeyUsageDataEncipherment,
	stdx509.KeyUsageKeyAgreement,
	stdx509.KeyUsageCertSign,
	stdx509.KeyUsageCRLSign,
	stdx509.KeyUsageEncipherOnly,
	stdx509.KeyUsageDecipherOnly,
}

// keyUsages names the bits set in usage. Each bit is named on its own because a
// combined mask is not a named constant.
func keyUsages(usage stdx509.KeyUsage) []string {
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
func extendedKeyUsages(cert *stdx509.Certificate) []string {
	usages := xslices.Map(cert.ExtKeyUsage, func(usage stdx509.ExtKeyUsage) string {
		return usage.String()
	})
	unknown := xslices.Map(cert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) string {
		return oid.String()
	})
	return append(usages, unknown...)
}
