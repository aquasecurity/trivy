package cache

import (
	"os"
	"path/filepath"
)

type TrivyCache interface {
	DefaultDir() string
	GetChecksDir() string
	GetComplianceSpecsDir() string
}

type RealCache struct{}

// DefaultDir returns/creates the cache-dir to be used for trivy operations
func (rc RealCache) DefaultDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

func (rc RealCache) GetChecksDir() string {
	return filepath.Join(rc.DefaultDir(), "policy")
}

func (rc RealCache) GetComplianceSpecsDir() string {
	return filepath.Join(rc.GetChecksDir(), "content", "specs", "compliance")
}
