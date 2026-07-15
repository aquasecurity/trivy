package crypto

import (
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/set"
)

var requiredExtensions = set.NewCaseInsensitive(".pem", ".der", ".crt", ".cer", ".key")

// Required reports whether filePath has an extension that may contain a cryptographic object.
func Required(filePath string) bool {
	return requiredExtensions.Contains(filepath.Ext(filePath))
}
