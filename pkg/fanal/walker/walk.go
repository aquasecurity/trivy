package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const defaultSizeThreshold = int64(100) << 20 // 200MB

var defaultSkipDirs = []string{
	// Scan .git/ metadata (e.g. .git/config, .git/credentials) for secrets, but
	// skip subdirectories that are either binary-heavy or high-volume with no
	// secret value:
	//   objects  – packed git object store; binary, can be very large
	//   lfs      – Git LFS binary data
	//   modules  – submodule checkouts
	//   logs     – reflog entries; plaintext but high-volume and low-signal
	"**/.git/objects",
	"**/.git/lfs",
	"**/.git/modules",
	"**/.git/logs",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
