package jks

import (
	"context"
	"errors"
	"iter"

	"golang.org/x/crypto/cryptobyte"

	"github.com/aquasecurity/trivy/pkg/crypto/parser/x509"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// The layout follows the engineStore method of sun.security.provider.JavaKeyStore, as the
// format has no specification. See
// https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/provider/JavaKeyStore.java
const (
	magic = 0xFEEDFEED

	// version1 stores certificates without their type, which is always X.509.
	version1 = 1
	version2 = 2

	tagPrivateKey  = 1
	tagTrustedCert = 2
)

// maxObjects bounds the number of certificates and private keys read from one keystore. A real
// trust store holds a few hundred.
const maxObjects = 10000

const certificateTypeX509 = "X.509"

// ErrNotJKS means that the content is not a JKS file.
var ErrNotJKS = errors.New("not a JKS file")

// Parse describes the certificates and encrypted private keys of a JKS keystore as assets.
//
// Content that is not a JKS file gives ErrNotJKS. Material that cannot be read is logged
// and skipped. Any other error means a parsed object could not be described.
func Parse(ctx context.Context, filePath string, content []byte) ([]ftypes.CryptoAsset, error) {
	s := cryptobyte.String(content)
	var m uint32
	if !s.ReadUint32(&m) || m != magic {
		return nil, ErrNotJKS
	}
	ctx = log.WithContextPrefix(ctx, "jks")
	ctx = log.WithContextAttrs(ctx, log.FilePath(filePath))
	return x509.ParseKeystoreObjects(ctx, filePath, objects(ctx, s), ftypes.CryptoKeystoreJKS)
}

// objects yields each trusted certificate, and each private key with the certificates of its
// chain.
func objects(ctx context.Context, data []byte) iter.Seq[x509.KeystoreObject] {
	return func(yield func(x509.KeystoreObject) bool) {
		s := cryptobyte.String(data)
		var version, count uint32
		if !s.ReadUint32(&version) || !s.ReadUint32(&count) {
			log.WarnContext(ctx, "Malformed JKS file")
			return
		}
		if version != version1 && version != version2 {
			log.WarnContext(ctx, "Unsupported JKS version", log.Int("version", int(version)))
			return
		}

		budget := maxObjects
		next := func(obj x509.KeystoreObject) bool {
			if budget == 0 {
				log.WarnContext(ctx, "Too many JKS objects")
				return false
			}
			budget--
			return yield(obj)
		}

		// An entry carries no length of its own, so the rest of the file is lost after a
		// malformed entry.
		for range count {
			var tag uint32
			var alias cryptobyte.String
			if !s.ReadUint32(&tag) || !s.ReadUint16LengthPrefixed(&alias) || !s.Skip(8) {
				log.WarnContext(ctx, "Malformed JKS entry")
				return
			}

			var ok bool
			switch tag {
			case tagPrivateKey:
				ok = readPrivateKeyEntry(ctx, &s, version, next)
			case tagTrustedCert:
				ok = readCertificate(ctx, &s, version, next)
			default:
				log.WarnContext(ctx, "Malformed JKS entry", log.Int("tag", int(tag)))
				return
			}
			if !ok {
				return
			}
		}
	}
}

// readPrivateKeyEntry yields the encrypted key of an entry and the certificates of its
// chain. It reports whether reading can continue.
func readPrivateKeyEntry(ctx context.Context, s *cryptobyte.String, version uint32, yield func(x509.KeystoreObject) bool) bool {
	var chainLen uint32
	var key []byte
	if !readUint32LengthPrefixed(s, &key) || !s.ReadUint32(&chainLen) {
		log.WarnContext(ctx, "Malformed JKS entry")
		return false
	}
	// The key is an EncryptedPrivateKeyInfo with the algorithm of the JKS key protector.
	if !yield(x509.KeystoreObject{Kind: x509.KeystoreEncryptedPrivateKey, DER: key}) {
		return false
	}
	for range chainLen {
		if !readCertificate(ctx, s, version, yield) {
			return false
		}
	}
	return true
}

// readCertificate yields one certificate of an entry. It reports whether reading can
// continue.
func readCertificate(ctx context.Context, s *cryptobyte.String, version uint32, yield func(x509.KeystoreObject) bool) bool {
	certType := certificateTypeX509
	if version == version2 {
		var t cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&t) {
			log.WarnContext(ctx, "Malformed JKS certificate")
			return false
		}
		certType = string(t)
	}

	var der []byte
	if !readUint32LengthPrefixed(s, &der) {
		log.WarnContext(ctx, "Malformed JKS certificate")
		return false
	}
	if certType != certificateTypeX509 {
		log.DebugContext(ctx, "Unsupported JKS certificate type", log.String("cert_type", certType))
		return true
	}
	return yield(x509.KeystoreObject{Kind: x509.KeystoreCertificate, DER: der})
}

// readUint32LengthPrefixed reads bytes prefixed with their 32-bit length.
func readUint32LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	var n uint32
	return s.ReadUint32(&n) && s.ReadBytes(out, int(n))
}
