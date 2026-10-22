package pkcs12

import (
	"context"
	"encoding/asn1"
	"errors"
	"iter"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	// maxDepth bounds the nesting of safe contents bags, which a well-formed keystore does not use.
	maxDepth = 8

	// maxBags bounds the number of contents and bags read from one keystore. A real trust store
	// holds a few hundred.
	maxBags = 10000
)

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedDataContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidCertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}

	oidX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// ErrNotPKCS12 is returned by Parse for content that is not a PKCS#12 file in DER.
var ErrNotPKCS12 = errors.New("not a PKCS#12 file")

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
// Content that is not a PKCS#12 file in DER gives ErrNotPKCS12. Material that cannot be read
// is logged and skipped. Any other error means a parsed certificate could not be described.
func Parse(ctx context.Context, filePath string, content []byte) ([]ftypes.CryptoAsset, error) {
	var p pfx
	if err := unmarshal(content, &p); err != nil || p.Version != 3 {
		return nil, ErrNotPKCS12
	}
	ctx = log.WithContextPrefix(ctx, "pkcs12")
	ctx = log.WithContextAttrs(ctx, log.FilePath(filePath))
	return x509.ParseCertificates(ctx, filePath, certificates(ctx, p), ftypes.CryptoKeystorePKCS12)
}

// certificates yields the DER of each certificate stored in an unencrypted content of the
// authenticated safe of p.
func certificates(ctx context.Context, p pfx) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		rest, ok := authenticatedSafe(ctx, p)
		if !ok {
			return
		}
		w := &walker{ctx: ctx, budget: maxBags, yield: yield}
		for len(rest) > 0 {
			if !w.spend() {
				return
			}
			var ci contentInfo
			var err error
			if rest, err = asn1.Unmarshal(rest, &ci); err != nil {
				log.WarnContext(ctx, "Malformed PKCS#12 file", log.Err(err))
				return
			}
			switch {
			case ci.ContentType.Equal(oidDataContentType):
				var data []byte
				if err := unmarshal(ci.Content.Bytes, &data); err != nil {
					log.WarnContext(ctx, "Malformed PKCS#12 content", log.Err(err))
					continue
				}
				if !w.walk(data, 0) {
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

// authenticatedSafe returns the encoded contents of the authenticated safe of p, which is
// stored as data in a keystore protected by a password-based MAC or by no integrity mode at
// all.
func authenticatedSafe(ctx context.Context, p pfx) ([]byte, bool) {
	if p.AuthSafe.ContentType.Equal(oidSignedDataContentType) {
		log.DebugContext(ctx, "PKCS#12 signed with a public key skipped")
		return nil, false
	}
	if !p.AuthSafe.ContentType.Equal(oidDataContentType) {
		log.WarnContext(ctx, "Malformed PKCS#12 file")
		return nil, false
	}

	var data []byte
	if err := unmarshal(p.AuthSafe.Content.Bytes, &data); err != nil {
		log.WarnContext(ctx, "Malformed PKCS#12 file", log.Err(err))
		return nil, false
	}
	contentInfos, err := sequence(data)
	if err != nil {
		log.WarnContext(ctx, "Malformed PKCS#12 file", log.Err(err))
		return nil, false
	}
	return contentInfos, true
}

// walker reads the certificates of one keystore and passes each to yield. The bags of the
// whole keystore share one budget.
type walker struct {
	ctx    context.Context
	budget int
	yield  func([]byte) bool
}

// walk yields the certificates of a safe contents structure and of the safe contents nested
// in it. It reports false when the walk has to stop, because yield asks to stop or the
// budget runs out.
func (w *walker) walk(der []byte, depth int) bool {
	if depth > maxDepth {
		log.WarnContext(w.ctx, "PKCS#12 safe contents nested too deep")
		return true
	}

	rest, err := sequence(der)
	if err != nil {
		log.WarnContext(w.ctx, "Malformed PKCS#12 safe contents", log.Err(err))
		return true
	}

	for len(rest) > 0 {
		if !w.spend() {
			return false
		}
		var bag safeBag
		if rest, err = asn1.Unmarshal(rest, &bag); err != nil {
			log.WarnContext(w.ctx, "Malformed PKCS#12 safe contents", log.Err(err))
			return true
		}
		switch {
		case bag.ID.Equal(oidCertBag):
			var cert certBag
			if err := unmarshal(bag.Value.Bytes, &cert); err != nil {
				log.WarnContext(w.ctx, "Malformed PKCS#12 certificate bag", log.Err(err))
				continue
			}
			if !cert.ID.Equal(oidX509Certificate) {
				log.DebugContext(w.ctx, "Unsupported PKCS#12 certificate type", log.String("cert_type", cert.ID.String()))
				continue
			}
			if !w.yield(cert.Data) {
				return false
			}
		case bag.ID.Equal(oidSafeContentsBag):
			if !w.walk(bag.Value.Bytes, depth+1) {
				return false
			}
		default:
			log.DebugContext(w.ctx, "PKCS#12 bag skipped", log.String("bag_type", bag.ID.String()))
		}
	}
	return true
}

// spend takes one bag from the budget and reports false when none is left.
func (w *walker) spend() bool {
	if w.budget == 0 {
		log.WarnContext(w.ctx, "Too many PKCS#12 bags")
		return false
	}
	w.budget--
	return true
}

// sequence returns the encoded elements of the SEQUENCE in der. The elements are decoded one
// at a time, because encoding/asn1 takes far more memory for a decoded element than for its
// DER.
func sequence(der []byte) ([]byte, error) {
	var seq asn1.RawValue
	if err := unmarshal(der, &seq); err != nil {
		return nil, err
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, xerrors.New("not a SEQUENCE")
	}
	return seq.Bytes, nil
}

// unmarshal decodes der into out and rejects trailing data.
func unmarshal(der []byte, out any) error {
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return xerrors.Errorf("%d bytes of trailing data", len(rest))
	}
	return nil
}
