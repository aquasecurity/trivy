package types

import (
	"strings"

	purl "github.com/package-url/packageurl-go"
)

const (
	PkgIdFormatCPE     = "cpe"
	PkgIdFormatPURL    = "purl"
	PkgIdFormatUnknown = "unknown"
)

// PkgIdentifier represents a software identifiers in any of the supported formats.
type PkgIdentifier struct {
	// Format is the software identifier format (e.g. CoSWID, CPE, PURL, etc.)
	Format string
	// Value represents the software identifier value
	Value string
}

// NewPkgIdentifier returns a new PkgIdentifier instance
func NewPkgIdentifier(value string) *PkgIdentifier {
	format := PkgIdFormatUnknown
	switch {
	case isCPE(value):
		format = PkgIdFormatCPE
	case isPURL(value):
		format = PkgIdFormatPURL
	}

	return &PkgIdentifier{
		Format: format,
		Value:  value,
	}
}

func isCPE(value string) bool {
	// TODO: properly validate CPE with a regex
	// ref: https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
	return strings.HasPrefix(value, "cpe:2.3")
}

func isPURL(value string) bool {
	_, err := purl.FromString(value)
	return err == nil
}
