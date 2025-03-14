package walker_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func TestSkipFile(t *testing.T) {
	tests := []struct {
		name      string
		skipFiles []string
		wants     map[string]bool
	}{
		{
			name:      "single star",
			skipFiles: []string{"/etc/*"},
			wants: map[string]bool{
				"/etc/foo":     true,
				"/etc/foo/bar": false,
			},
		},
		{
			name:      "two stars",
			skipFiles: []string{"/etc/*/*"},
			wants: map[string]bool{
				"/etc/foo":     false,
				"/etc/foo/bar": true,
			},
		},
		{
			name:      "double star",
			skipFiles: []string{"**/*.txt"},
			wants: map[string]bool{
				"/etc/foo":         false,
				"/etc/foo/bar":     false,
				"/var/log/bar.txt": true,
			},
		},
		{
			name: "multiple skip files",
			skipFiles: []string{
				"/etc/*/*",
				"/var/log/*.txt",
			},
			wants: map[string]bool{
				"/etc/foo":         false,
				"/etc/foo/bar":     true,
				"/var/log/bar.txt": true,
			},
		},
		{
			name:      "error bad pattern",
			skipFiles: []string{`[^etc`}, // filepath.Match returns ErrBadPattern
			wants: map[string]bool{
				"/etc/foo":     false,
				"/etc/foo/bar": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for file, want := range tt.wants {
				file = filepath.ToSlash(filepath.Clean(file))
				got := utils.SkipPath(file, utils.CleanSkipPaths(tt.skipFiles))
				assert.Equal(t, want, got, "skipFiles: %s, file: %s", tt.skipFiles, file)
			}
		})
	}
}

func TestSkipDir(t *testing.T) {
	tests := []struct {
		name     string
		skipDirs []string
		wants    map[string]bool
	}{
		{
			name: "default skip dirs",
			skipDirs: []string{
				"**/.git",
				"proc",
				"sys",
				"dev",
			},
			wants: map[string]bool{
				".git":    true,
				"proc":    true,
				"foo.bar": false,
			},
		},
		{
			name:     "single star",
			skipDirs: []string{"/*"},
			wants: map[string]bool{
				"/etc":         true,
				"/etc/foo/bar": false,
			},
		},
		{
			name:     "two stars",
			skipDirs: []string{"/etc/*/*"},
			wants: map[string]bool{
				"/etc/foo":     false,
				"/etc/foo/bar": true,
			},
		},
		{
			name: "multiple dirs",
			skipDirs: []string{
				"/etc/*/*",
				"/var/log/*",
			},
			wants: map[string]bool{
				"/etc/foo":     false,
				"/etc/foo/bar": true,
				"/var/log/bar": true,
			},
		},
		{
			name:     "double star",
			skipDirs: []string{"**/.terraform"},
			wants: map[string]bool{
				".terraform":              true,
				"test/foo/bar/.terraform": true,
			},
		},
		{
			name:     "error bad pattern",
			skipDirs: []string{`[^etc`}, // filepath.Match returns ErrBadPattern
			wants: map[string]bool{
				"/etc/foo":     false,
				"/etc/foo/bar": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for dir, want := range tt.wants {
				dir = filepath.ToSlash(filepath.Clean(dir))
				got := utils.SkipPath(dir, utils.CleanSkipPaths(tt.skipDirs))
				assert.Equal(t, want, got, "defaultSkipDirs: %s, dir: %s", tt.skipDirs, dir)
			}
		})
	}
}
