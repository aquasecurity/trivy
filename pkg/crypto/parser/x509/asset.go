package x509

import (
	"context"
	stdx509 "crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

// objectToAssets describes a parsed object as assets. Material it cannot describe is
// logged and left out, and an error means the description itself is broken.
func objectToAssets(ctx context.Context, obj object) ([]ftypes.CryptoAssetInfo, error) {
	switch obj.kind {
	case objectCertificate:
		return describeCertificate(ctx, obj.certificate, obj.encoding)
	case objectPublicKey:
		return describeStandaloneKey(ctx, obj, ftypes.CryptoKeyTypePublic)
	case objectPrivateKey:
		return describeStandaloneKey(ctx, obj, ftypes.CryptoKeyTypePrivate)
	case objectEncryptedPrivateKey:
		return describeEncryptedPrivateKey(obj)
	default:
		return nil, xerrors.Errorf("object kind %d has no description", obj.kind)
	}
}

// describeCertificate describes a certificate, the algorithm it is signed with, the key
// it carries and the algorithm of that key. A key that cannot be described is left out,
// and the certificate keeps the relationships it can state.
func describeCertificate(
	ctx context.Context,
	cert certificate,
	encoding ftypes.CryptoEncoding,
) ([]ftypes.CryptoAssetInfo, error) {
	asset := ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindCertificate,
		Identity: ftypes.DigestIdentity(ftypes.CryptoMethodSHA256, cert.Raw),
		Name:     certificateName(cert.Certificate),

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
			MaxPathLen:     max(cert.MaxPathLen, 0),
			MaxPathLenZero: cert.MaxPathLenZero,
		},
	}

	// A signature algorithm gets no key parameters, because the key that produced the
	// signature belongs to the issuer, and this certificate stores the key of its subject.
	signature := crypto.DescribeAlgorithm(cert.signatureOID, 0, "")
	asset.Relationships = append(asset.Relationships, ftypes.CryptoRelationship{
		Type:         ftypes.CryptoRelationshipSignedWith,
		RelatedAsset: signature.Descriptor(),
	})
	related := []ftypes.CryptoAssetInfo{signature}

	// The key stays without a format and an encoding, because it is not a standalone
	// container.
	key, keyAlgorithm, err := crypto.DescribeKey(cert.PublicKey, ftypes.CryptoKeyTypePublic, "", "")
	switch {
	// TODO: cover a certificate whose key algorithm OID crypto/x509 does not recognize,
	// such as Ed448.
	case errors.Is(err, crypto.ErrNoCanonicalForm):
		log.DebugContext(ctx, "Certificate key not described", log.Err(err))
	case err != nil:
		return nil, err
	default:
		asset.Relationships = append(asset.Relationships, ftypes.CryptoRelationship{
			Type:         ftypes.CryptoRelationshipContains,
			RelatedAsset: key.Descriptor(),
		})
		related = append(related, key, keyAlgorithm)
	}

	return append([]ftypes.CryptoAssetInfo{asset}, related...), nil
}

// describeStandaloneKey describes a key object as the key itself and the algorithm it
// belongs to.
func describeStandaloneKey(
	ctx context.Context,
	obj object,
	keyType ftypes.CryptoKeyType,
) ([]ftypes.CryptoAssetInfo, error) {
	key, keyAlgorithm, err := crypto.DescribeKey(obj.publicKey, keyType, obj.keyFormat, obj.encoding)
	switch {
	case errors.Is(err, crypto.ErrNoCanonicalForm):
		log.DebugContext(ctx, "Key not described", log.Err(err))
		return nil, nil
	case err != nil:
		return nil, err
	}
	return []ftypes.CryptoAssetInfo{key, keyAlgorithm}, nil
}

// describeEncryptedPrivateKey describes an encrypted private key container. The container
// format selects the identification method, because each method digests a different
// canonical form.
func describeEncryptedPrivateKey(obj object) ([]ftypes.CryptoAssetInfo, error) {
	var method ftypes.CryptoIdentityMethod
	switch obj.encryption {
	case encryptionFormatPKCS8:
		method = ftypes.CryptoMethodEncryptedPKCS8SHA256
	case encryptionFormatRFC1423:
		method = ftypes.CryptoMethodEncryptedRFC1423SHA256
	default:
		return nil, xerrors.Errorf("encryption format %d has no identification method", obj.encryption)
	}

	key := crypto.DescribeEncryptedKey(method, obj.encrypted, obj.keyFormat, obj.encoding)
	return []ftypes.CryptoAssetInfo{key}, nil
}

// certificateName prefers the common name and falls back to the full distinguished
// name, which is the only subject identifier some certificates carry.
func certificateName(cert *stdx509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
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
