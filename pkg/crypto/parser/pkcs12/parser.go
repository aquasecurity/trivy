package pkcs12

import (
	"context"
	"encoding/asn1"
	"iter"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// maxDepth bounds the nesting of safe contents bags, which a well-formed keystore does not use.
const maxDepth = 8

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedDataContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidCertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}

	oidX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// pfx is the outer structure of a PKCS#12 file, as defined in RFC 7292.
type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

// contentInfo is a PKCS#7 content, as defined in RFC 2315.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"tag:0,explicit"`
	Attributes asn1.RawValue `asn1:"optional"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

// Parse describes the unencrypted certificates of a PKCS#12 keystore as assets.
//
// Material that cannot be read is logged and skipped. An error means a parsed certificate
// could not be described.
func Parse(ctx context.Context, filePath string, content []byte) ([]ftypes.CryptoAsset, error) {
	ctx = log.WithContextPrefix(ctx, "pkcs12")
	ctx = log.WithContextAttrs(ctx, log.FilePath(filePath))
	return x509.ParseCertificates(ctx, filePath, certificates(ctx, content), ftypes.CryptoEncodingPKCS12)
}

// certificates yields the DER of each certificate stored in an unencrypted content of the
// authenticated safe.
func certificates(ctx context.Context, content []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		contents, ok := authenticatedSafe(ctx, content)
		if !ok {
			return
		}
		for _, ci := range contents {
			switch {
			case ci.ContentType.Equal(oidDataContentType):
				var data []byte
				if rest, err := asn1.Unmarshal(ci.Content.Bytes, &data); err != nil || len(rest) != 0 {
					log.WarnContext(ctx, "Malformed PKCS#12 content")
					continue
				}
				if !walkSafeContents(ctx, data, 0, yield) {
					return
				}
			case ci.ContentType.Equal(oidEncryptedDataContentType), ci.ContentType.Equal(oidEnvelopedDataContentType):
				log.DebugContext(ctx, "Encrypted PKCS#12 content skipped")
			default:
				log.DebugContext(ctx, "Unsupported PKCS#12 content", log.String("content_type", ci.ContentType.String()))
			}
		}
	}
}

// authenticatedSafe reads the contents of the authenticated safe, which is stored as data
// in a keystore protected by a password-based MAC or by no integrity mode at all.
func authenticatedSafe(ctx context.Context, content []byte) ([]contentInfo, bool) {
	// Files are selected by name, which other formats share.
	if len(content) == 0 || content[0] != byte(asn1.TagSequence)|0x20 {
		log.DebugContext(ctx, "No PKCS#12 file found")
		return nil, false
	}
	// An indefinite length is allowed by BER, which encoding/asn1 does not read.
	if len(content) > 1 && content[1] == 0x80 {
		log.DebugContext(ctx, "PKCS#12 with an indefinite length is not supported")
		return nil, false
	}

	var p pfx
	rest, err := asn1.Unmarshal(content, &p)
	if err != nil || len(rest) != 0 || p.Version != 3 {
		log.WarnContext(ctx, "Malformed PKCS#12 file")
		return nil, false
	}
	if p.AuthSafe.ContentType.Equal(oidSignedDataContentType) {
		log.DebugContext(ctx, "PKCS#12 signed with a public key skipped")
		return nil, false
	}
	if !p.AuthSafe.ContentType.Equal(oidDataContentType) {
		log.WarnContext(ctx, "Malformed PKCS#12 file")
		return nil, false
	}

	var data []byte
	if rest, err := asn1.Unmarshal(p.AuthSafe.Content.Bytes, &data); err != nil || len(rest) != 0 {
		log.WarnContext(ctx, "Malformed PKCS#12 file")
		return nil, false
	}
	var contents []contentInfo
	if rest, err := asn1.Unmarshal(data, &contents); err != nil || len(rest) != 0 {
		log.WarnContext(ctx, "Malformed PKCS#12 file")
		return nil, false
	}
	return contents, true
}

// walkSafeContents yields the certificates of a safe contents structure and of the safe
// contents nested in it. It reports false when yield asks to stop.
func walkSafeContents(ctx context.Context, der []byte, depth int, yield func([]byte) bool) bool {
	if depth > maxDepth {
		log.WarnContext(ctx, "PKCS#12 safe contents nested too deep")
		return true
	}

	var bags []safeBag
	if rest, err := asn1.Unmarshal(der, &bags); err != nil || len(rest) != 0 {
		log.WarnContext(ctx, "Malformed PKCS#12 safe contents")
		return true
	}

	for _, bag := range bags {
		switch {
		case bag.ID.Equal(oidCertBag):
			var cert certBag
			if rest, err := asn1.Unmarshal(bag.Value.Bytes, &cert); err != nil || len(rest) != 0 {
				log.WarnContext(ctx, "Malformed PKCS#12 certificate bag")
				continue
			}
			if !cert.ID.Equal(oidX509Certificate) {
				log.DebugContext(ctx, "Unsupported PKCS#12 certificate type", log.String("cert_type", cert.ID.String()))
				continue
			}
			if !yield(cert.Data) {
				return false
			}
		case bag.ID.Equal(oidSafeContentsBag):
			if !walkSafeContents(ctx, bag.Value.Bytes, depth+1, yield) {
				return false
			}
		default:
			log.DebugContext(ctx, "PKCS#12 bag skipped", log.String("bag_type", bag.ID.String()))
		}
	}
	return true
}
