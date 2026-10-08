package x509

// Bridge to expose the ASN.1 structures the parser reads to tests in the x509_test package.

// EncryptedPrivateKeyInfo exports encryptedPrivateKeyInfo for testing.
type EncryptedPrivateKeyInfo = encryptedPrivateKeyInfo

// PKCS1PrivateKey exports pkcs1PrivateKey for testing.
type PKCS1PrivateKey = pkcs1PrivateKey

// PKCS1AdditionalPrime exports pkcs1AdditionalPrime for testing.
type PKCS1AdditionalPrime = pkcs1AdditionalPrime

// PKCS8PrivateKey exports pkcs8PrivateKey for testing.
type PKCS8PrivateKey = pkcs8PrivateKey

// OIDRSAEncryption exports oidRSAEncryption for testing.
var OIDRSAEncryption = oidRSAEncryption
