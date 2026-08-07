package crypto

import "time"

// CertificateFormat identifies a certificate serialization format.
type CertificateFormat string

const (
	// CertificateFormatX509 identifies an X.509 certificate.
	CertificateFormatX509 CertificateFormat = "X.509"
)

// Certificate contains certificate-specific metadata.
type Certificate struct {
	Subject               string            `json:",omitempty"`
	Issuer                string            `json:",omitempty"`
	SerialNumber          string            `json:",omitempty"`
	NotBefore             time.Time         `json:",omitzero"`
	NotAfter              time.Time         `json:",omitzero"`
	Format                CertificateFormat `json:",omitempty"`
	KeyUsage              []string          `json:",omitempty"`
	ExtendedKeyUsage      []string          `json:",omitempty"`
	DNSNames              []string          `json:",omitempty"`
	EmailAddresses        []string          `json:",omitempty"`
	IPAddresses           []string          `json:",omitempty"`
	URIs                  []string          `json:",omitempty"`
	BasicConstraintsValid bool              `json:",omitempty"`
	IsCA                  bool              `json:",omitempty"`
	// MaxPathLen is the maximum number of non-self-issued intermediate
	// certificates. Zero with MaxPathLenZero unset means no constraint was
	// specified; negative sentinel values are not retained in this model.
	MaxPathLen int `json:",omitempty"`
	// MaxPathLenZero reports whether zero is an explicit maximum path length.
	MaxPathLenZero bool `json:",omitempty"`
}
