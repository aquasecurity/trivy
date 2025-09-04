package rootio

import (
	"github.com/aquasecurity/trivy/pkg/detector/library"
)

func init() {
	// Register the rootio provider when this package is imported
	library.RegisterProvider(Provider)
}
