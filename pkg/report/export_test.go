package report

import (
	"net/url"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// Bridge to expose report internals to tests in the report_test package.

// ClearURI exports clearURI for testing.
func ClearURI(s string) string {
	return clearURI(s)
}

// ToProperties exports toProperties for testing.
func ToProperties(title, severity, cvssScore string, cvssData map[string]any) sarif.Properties {
	return toProperties(title, severity, cvssScore, cvssData)
}

// ToUri exports toUri for testing.
func ToUri(s string) *url.URL {
	return toUri(s)
}
