package x509

import (
	"context"
	"fmt"
	"iter"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// KeystoreObjectKind identifies the structure of a DER object read out of a keystore.
type KeystoreObjectKind uint8

const (
	// KeystoreCertificate identifies an X.509 certificate.
	KeystoreCertificate KeystoreObjectKind = iota + 1
	// KeystorePrivateKey identifies a PKCS#8 PrivateKeyInfo.
	KeystorePrivateKey
	// KeystoreEncryptedPrivateKey identifies a PKCS#8 EncryptedPrivateKeyInfo.
	KeystoreEncryptedPrivateKey
)

func (k KeystoreObjectKind) String() string {
	switch k {
	case KeystoreCertificate:
		return "certificate"
	case KeystorePrivateKey:
		return "private key"
	case KeystoreEncryptedPrivateKey:
		return "encrypted private key"
	default:
		return fmt.Sprintf("KeystoreObjectKind(%d)", uint8(k))
	}
}

// KeystoreObject is a DER object read out of a keystore.
type KeystoreObject struct {
	Kind KeystoreObjectKind
	DER  []byte
}

// ParseKeystoreObjects describes DER objects stored in the given keystore as assets. An
// object that cannot be read is logged and skipped, and a repeated asset is reported once.
func ParseKeystoreObjects(ctx context.Context, filePath string, objects iter.Seq[KeystoreObject], keystore ftypes.CryptoKeystoreType) ([]ftypes.CryptoAsset, error) {
	parsed := func(yield func(object) bool) {
		for o := range objects {
			obj, err := parseKeystoreObject(o)
			if err != nil {
				logParseError(ctx, err, log.String("keystore_object", o.Kind.String()))
				continue
			}
			obj.encoding = ftypes.CryptoEncodingDER
			obj.keystore = keystore
			if !yield(obj) {
				return
			}
		}
	}
	return describe(filePath, parsed)
}

func parseKeystoreObject(o KeystoreObject) (object, error) {
	switch o.Kind {
	case KeystoreCertificate:
		return certificateObject(o.DER)
	case KeystorePrivateKey:
		return pkcs8PrivateKeyObject(o.DER)
	case KeystoreEncryptedPrivateKey:
		return encryptedPKCS8Object(o.DER)
	default:
		return object{}, errUnsupportedCrypto
	}
}
