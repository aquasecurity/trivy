package cyclonedx

import (
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

// ellipticCurves maps the curve names of crypto/elliptic to the CycloneDX elliptic curve
// enumeration, which qualifies a curve with the body that standardized it. A curve absent
// from the map is left out, because the enumeration accepts nothing else.
var ellipticCurves = map[string]string{
	"P-256": "nist/P-256",
	"P-384": "nist/P-384",
	"P-521": "nist/P-521",
}

// marshalCryptoComponent turns a cryptographic asset into a CycloneDX component.
func (m *Marshaler) marshalCryptoComponent(component *core.CryptoComponent) cdx.Component {
	return cdx.Component{
		BOMRef:           component.BOMRef(),
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             component.Asset.Name,
		CryptoProperties: m.cryptoProperties(component.Asset),
		Evidence:         m.evidence(component.Occurrences),
	}
}

// cryptoProperties translates a cryptographic asset into CycloneDX crypto properties.
// This is the only place where the neutral model meets the CycloneDX types.
func (m *Marshaler) cryptoProperties(asset ftypes.CryptoAssetInfo) *cdx.CryptoProperties {
	// A report can come from a JSON file, through `trivy convert`, and nothing validates it,
	// so the detail is checked and not assumed from the kind.
	switch {
	case asset.Kind == ftypes.CryptoKindCertificate && asset.Certificate != nil:
		return &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: m.certificateProperties(asset),
		}
	case asset.Kind == ftypes.CryptoKindKey && asset.Key != nil:
		return &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: m.relatedCryptoMaterialProperties(asset),
		}
	case asset.Kind == ftypes.CryptoKindAlgorithm && asset.Algorithm != nil:
		return &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: m.algorithmProperties(asset),
			OID:                 asset.Identity.Value,
		}
	}

	// Either the kind is unknown, or the details it names are missing.
	m.logger.Debug("Skipping the cryptographic asset that has no details matching its kind",
		log.String("bom-ref", core.CryptoBOMRef(asset.Descriptor())), log.Any("kind", asset.Kind))
	return nil
}

func (m *Marshaler) certificateProperties(asset ftypes.CryptoAssetInfo) *cdx.CertificateProperties {
	cert := asset.Certificate
	return &cdx.CertificateProperties{
		SerialNumber:      cert.SerialNumber,
		SubjectName:       cert.Subject,
		IssuerName:        cert.Issuer,
		NotValidBefore:    formatTime(cert.NotBefore),
		NotValidAfter:     formatTime(cert.NotAfter),
		CertificateFormat: string(cert.Format),
		// The identity is the digest of the whole DER, the fingerprint openssl and browsers
		// report. The 1.7 schema describes this field as a hash of the certificate
		// "excluding it's signature", which is a digest nothing else computes.
		// https://github.com/CycloneDX/specification/issues/1031
		Fingerprint: &cdx.Hash{
			Algorithm: cdx.HashAlgoSHA256,
			Value:     asset.Identity.Value,
		},
		CertificateExtensions:      m.certificateExtensions(cert),
		RelatedCryptographicAssets: m.relatedCryptographicAssets(asset.Relationships),
	}
}

// certificateExtensions renders the parsed extensions as the strings CycloneDX expects,
// following the notation of the OpenSSL text output.
func (*Marshaler) certificateExtensions(cert *ftypes.CryptoCertificate) *[]cdx.CertificateExtension {
	var extensions []cdx.CertificateExtension
	add := func(name cdx.CertificateExtensionName, value string) {
		extensions = append(extensions, cdx.CertificateExtension{
			Common: &cdx.CommonCertificateExtension{
				Name:  name,
				Value: value,
			},
		})
	}

	if cert.BasicConstraintsValid {
		value := "CA:FALSE"
		if cert.IsCA {
			value = "CA:TRUE"
		}
		// A path length is stated only by a CA that constrains the chain below it. Zero is
		// such a constraint, and an unset zero is not, so the two are told apart by the flag.
		if cert.IsCA && (cert.MaxPathLen > 0 || cert.MaxPathLenZero) {
			value += ", pathlen:" + strconv.Itoa(cert.MaxPathLen)
		}
		add(cdx.CertExtBasicConstraints, value)
	}
	if len(cert.KeyUsage) != 0 {
		add(cdx.CertExtKeyUsage, strings.Join(cert.KeyUsage, ", "))
	}
	if len(cert.ExtendedKeyUsage) != 0 {
		add(cdx.CertExtExtendedKeyUsage, strings.Join(cert.ExtendedKeyUsage, ", "))
	}
	// Each subject alternative name states its own type, because one extension holds names
	// of every type at once.
	names := prefixAll("DNS:", cert.DNSNames)
	names = append(names, prefixAll("email:", cert.EmailAddresses)...)
	names = append(names, prefixAll("IP:", cert.IPAddresses)...)
	names = append(names, prefixAll("URI:", cert.URIs)...)
	if len(names) != 0 {
		add(cdx.CertExtSubjectAlternativeName, strings.Join(names, ", "))
	}

	if len(extensions) == 0 {
		return nil
	}
	return &extensions
}

func (m *Marshaler) relatedCryptoMaterialProperties(asset ftypes.CryptoAssetInfo) *cdx.RelatedCryptoMaterialProperties {
	key := asset.Key
	properties := &cdx.RelatedCryptoMaterialProperties{
		Type:                       relatedCryptoMaterialType(asset.KeyType),
		Format:                     string(key.Format),
		RelatedCryptographicAssets: m.relatedCryptographicAssets(asset.Relationships),
	}
	if key.Size > 0 {
		properties.Size = new(key.Size)
	}
	// The schema asks for a hash of the asset, and both key identities are one: the digest
	// of the SubjectPublicKeyInfo, or of the container when it stays encrypted.
	properties.Fingerprint = &cdx.Hash{
		Algorithm: cdx.HashAlgoSHA256,
		Value:     asset.Identity.Value,
	}
	return properties
}

func (m *Marshaler) algorithmProperties(asset ftypes.CryptoAssetInfo) *cdx.CryptoAlgorithmProperties {
	properties := &cdx.CryptoAlgorithmProperties{
		Primitive:       cryptoPrimitive(asset.Algorithm.Primitive),
		AlgorithmFamily: asset.Algorithm.Family,
	}

	// The property that distinguishes algorithms sharing one OID is kept as a parameter of
	// the identity, and only its value is reported here.
	name, value, found := asset.Identity.AlgorithmParameter()
	if !found {
		return properties
	}
	switch name {
	case ftypes.CryptoParameterKeySize:
		properties.ParameterSetIdentifier = value
	case ftypes.CryptoParameterCurve:
		properties.EllipticCurve = ellipticCurves[value]
	}
	return properties
}

// relatedCryptographicAssets refers to the neighboring assets. CycloneDX describes what
// the target is rather than how it is related, so the relationship types of the model
// collapse into the kind of the target.
func (*Marshaler) relatedCryptographicAssets(relationships []ftypes.CryptoRelationship) *[]cdx.RelatedCryptographicAsset {
	if len(relationships) == 0 {
		return nil
	}

	related := xslices.Map(relationships, func(relationship ftypes.CryptoRelationship) cdx.RelatedCryptographicAsset {
		return cdx.RelatedCryptographicAsset{
			Type: relatedCryptographicAssetType(relationship.RelatedAsset),
			Ref:  core.CryptoBOMRef(relationship.RelatedAsset),
		}
	})
	return &related
}

func relatedCryptographicAssetType(descriptor ftypes.CryptoDescriptor) string {
	if descriptor.Kind == ftypes.CryptoKindKey {
		if descriptor.KeyType == ftypes.CryptoKeyTypePrivate {
			return "privateKey"
		}
		return "publicKey"
	}
	return "algorithm"
}

func relatedCryptoMaterialType(keyType ftypes.CryptoKeyType) cdx.RelatedCryptoMaterialType {
	if keyType == ftypes.CryptoKeyTypePrivate {
		return cdx.RelatedCryptoMaterialTypePrivateKey
	}
	return cdx.RelatedCryptoMaterialTypePublicKey
}

func cryptoPrimitive(primitive ftypes.CryptoPrimitive) cdx.CryptoPrimitive {
	switch primitive {
	case ftypes.CryptoPrimitiveSignature:
		return cdx.CryptoPrimitiveSignature
	case ftypes.CryptoPrimitivePKE:
		return cdx.CryptoPrimitivePKE
	}
	return cdx.CryptoPrimitiveUnknown
}

// evidence reports where the component was found. A cryptographic asset is merged by
// identity, so one component has an occurrence per file it was found in.
func (*Marshaler) evidence(occurrences []core.Occurrence) *cdx.Evidence {
	if len(occurrences) == 0 {
		return nil
	}

	found := xslices.Map(occurrences, func(occurrence core.Occurrence) cdx.EvidenceOccurrence {
		return cdx.EvidenceOccurrence{Location: occurrence.Location}
	})
	return &cdx.Evidence{Occurrences: &found}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func prefixAll(prefix string, values []string) []string {
	return xslices.Map(values, func(value string) string {
		return prefix + value
	})
}
