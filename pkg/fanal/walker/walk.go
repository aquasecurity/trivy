package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const defaultSizeThreshold = int64(100) << 20 // 200MB

var defaultSkipDirs = []string{
	// Skip heavy binary subdirectories of .git/ for performance, but allow
	// .git/config to be scanned since it may contain credentials in remote URLs.
	"**/.git/objects",
	"**/.git/lfs",
	"**/.git/modules",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
