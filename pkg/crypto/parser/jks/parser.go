package jks

import (
	"context"
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

const certificateTypeX509 = "X.509"

// Parse describes the certificates of a JKS keystore as assets.
//
// Material that cannot be read is logged and skipped. An error means a parsed certificate
// could not be described.
func Parse(ctx context.Context, filePath string, content []byte) ([]ftypes.CryptoAsset, error) {
	ctx = log.WithContextPrefix(ctx, "jks")
	ctx = log.WithContextAttrs(ctx, log.FilePath(filePath))
	return x509.ParseCertificates(ctx, filePath, certificates(ctx, content), ftypes.CryptoEncodingJKS)
}

// certificates yields the DER of each trusted certificate and of each certificate in the
// chain of a private key.
func certificates(ctx context.Context, content []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		s := cryptobyte.String(content)
		var m, version, count uint32
		if !s.ReadUint32(&m) || m != magic {
			log.DebugContext(ctx, "No JKS file found")
			return
		}
		if !s.ReadUint32(&version) || !s.ReadUint32(&count) {
			log.WarnContext(ctx, "Malformed JKS file")
			return
		}
		if version != version1 && version != version2 {
			log.WarnContext(ctx, "Unsupported JKS version", log.Int("version", int(version)))
			return
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
				ok = readPrivateKeyEntry(ctx, &s, version, yield)
			case tagTrustedCert:
				ok = readCertificate(ctx, &s, version, yield)
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

// readPrivateKeyEntry skips the encrypted key of an entry and yields the certificates of
// its chain. It reports whether reading can continue.
func readPrivateKeyEntry(ctx context.Context, s *cryptobyte.String, version uint32, yield func([]byte) bool) bool {
	var keyLen, chainLen uint32
	if !s.ReadUint32(&keyLen) || !s.Skip(int(keyLen)) || !s.ReadUint32(&chainLen) {
		log.WarnContext(ctx, "Malformed JKS entry")
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
func readCertificate(ctx context.Context, s *cryptobyte.String, version uint32, yield func([]byte) bool) bool {
	certType := certificateTypeX509
	if version == version2 {
		var t cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&t) {
			log.WarnContext(ctx, "Malformed JKS certificate")
			return false
		}
		certType = string(t)
	}

	var certLen uint32
	var der []byte
	if !s.ReadUint32(&certLen) || !s.ReadBytes(&der, int(certLen)) {
		log.WarnContext(ctx, "Malformed JKS certificate")
		return false
	}
	if certType != certificateTypeX509 {
		log.DebugContext(ctx, "Unsupported JKS certificate type", log.String("cert_type", certType))
		return true
	}
	return yield(der)
}
