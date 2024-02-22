package scanners

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

type WriteFileFS interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type FSScanner interface {
	// Name provides the human-readable name of the scanner e.g. "CloudFormation"
	Name() string
	// ScanFS scans the given filesystem for issues, starting at the provided directory.
	// Use '.' to scan an entire filesystem.
	ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error)
}
