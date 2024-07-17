package cache

import (
	"os"
	"path/filepath"
)

// DefaultDir returns/creates the cache-dir to be used for trivy operations
func DefaultDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

func GetChecksDir() string {
	return filepath.Join(DefaultDir(), "/policy")
}

func GetComplianceSpecsDir() string {
	return filepath.Join(GetChecksDir(), "/content/specs/compliance")
}
