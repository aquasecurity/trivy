package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const defaultSizeThreshold = int64(100) << 20 // 200MB

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string

	// FollowSymlinks follows symlinks to regular files; dir symlinks are
	// never followed (avoids traversal cycles).
	FollowSymlinks bool
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
