package pkcs12

// Bridge to expose the ASN.1 structures and object identifiers the parser reads to tests in
// the pkcs12_test package.

// PFX exports pfx for testing.
type PFX = pfx

// ContentInfo exports contentInfo for testing.
type ContentInfo = contentInfo

// SafeBag exports safeBag for testing.
type SafeBag = safeBag

// CertBag exports certBag for testing.
type CertBag = certBag

var (
	// OIDDataContentType exports oidDataContentType for testing.
	OIDDataContentType = oidDataContentType
	// OIDSignedDataContentType exports oidSignedDataContentType for testing.
	OIDSignedDataContentType = oidSignedDataContentType
	// OIDEnvelopedDataContentType exports oidEnvelopedDataContentType for testing.
	OIDEnvelopedDataContentType = oidEnvelopedDataContentType
	// OIDEncryptedDataContentType exports oidEncryptedDataContentType for testing.
	OIDEncryptedDataContentType = oidEncryptedDataContentType
	// OIDCertBag exports oidCertBag for testing.
	OIDCertBag = oidCertBag
	// OIDSafeContentsBag exports oidSafeContentsBag for testing.
	OIDSafeContentsBag = oidSafeContentsBag
	// OIDX509Certificate exports oidX509Certificate for testing.
	OIDX509Certificate = oidX509Certificate
)

// MaxBags exports maxBags for testing.
const MaxBags = maxBags
