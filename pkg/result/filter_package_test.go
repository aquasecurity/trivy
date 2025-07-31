package result

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_isKernelPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  ftypes.Package
		want bool
	}{
		{
			name: "Debian kernel package with linux source",
			pkg: ftypes.Package{
				Name:    "linux-headers-5.15.0-56-generic",
				SrcName: "linux",
			},
			want: true,
		},
		{
			name: "Ubuntu kernel package with linux-* source",
			pkg: ftypes.Package{
				Name:    "linux-image-5.15.0-56-generic",
				SrcName: "linux-signed",
			},
			want: true,
		},
		{
			name: "RHEL kernel package",
			pkg: ftypes.Package{
				Name:    "kernel-core",
				SrcName: "kernel",
			},
			want: true,
		},
		{
			name: "Fedora kernel package",
			pkg: ftypes.Package{
				Name:    "kernel-modules-extra",
				SrcName: "kernel-modules-extra",
			},
			want: true,
		},
		{
			name: "Non-kernel package",
			pkg: ftypes.Package{
				Name:    "vim",
				SrcName: "vim",
			},
			want: false,
		},
		{
			name: "Package with linux in name but not source",
			pkg: ftypes.Package{
				Name:    "util-linux",
				SrcName: "util-linux",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isKernelPackage(tt.pkg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isDocumentationPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkgName string
		want    bool
	}{
		{
			name:    "doc package",
			pkgName: "vim-doc",
			want:    true,
		},
		{
			name:    "docs package",
			pkgName: "python3-docs",
			want:    true,
		},
		{
			name:    "license package",
			pkgName: "gcc-license",
			want:    true,
		},
		{
			name:    "debug package",
			pkgName: "libc-dbg",
			want:    true,
		},
		{
			name:    "debug package variant",
			pkgName: "glibc-debug",
			want:    true,
		},
		{
			name:    "regular package",
			pkgName: "vim",
			want:    false,
		},
		{
			name:    "package with doc in middle",
			pkgName: "document-viewer",
			want:    false,
		},
		{
			name:    "package with debug in middle",
			pkgName: "debugger-tools",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDocumentationPackage(tt.pkgName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isUnlikelyAffected(t *testing.T) {
	tests := []struct {
		name         string
		pkg          ftypes.Package
		artifactType ftypes.ArtifactType
		want         bool
	}{
		{
			name: "kernel package in container image",
			pkg: ftypes.Package{
				Name:    "linux-headers-5.15.0-56-generic",
				SrcName: "linux",
			},
			artifactType: ftypes.TypeContainerImage,
			want:         true,
		},
		{
			name: "kernel package in filesystem",
			pkg: ftypes.Package{
				Name:    "linux-headers-5.15.0-56-generic",
				SrcName: "linux",
			},
			artifactType: ftypes.TypeFilesystem,
			want:         false,
		},
		{
			name: "doc package in container image",
			pkg: ftypes.Package{
				Name:    "vim-doc",
				SrcName: "vim",
			},
			artifactType: ftypes.TypeContainerImage,
			want:         true,
		},
		{
			name: "doc package in filesystem",
			pkg: ftypes.Package{
				Name:    "vim-doc",
				SrcName: "vim",
			},
			artifactType: ftypes.TypeFilesystem,
			want:         true,
		},
		{
			name: "debug package in VM image",
			pkg: ftypes.Package{
				Name:    "libc-dbg",
				SrcName: "glibc",
			},
			artifactType: ftypes.TypeVM,
			want:         true,
		},
		{
			name: "regular package in container image",
			pkg: ftypes.Package{
				Name:    "vim",
				SrcName: "vim",
			},
			artifactType: ftypes.TypeContainerImage,
			want:         false,
		},
		{
			name: "license package in container image",
			pkg: ftypes.Package{
				Name:    "gcc-license",
				SrcName: "gcc",
			},
			artifactType: ftypes.TypeContainerImage,
			want:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnlikelyAffected(tt.pkg, tt.artifactType)
			assert.Equal(t, tt.want, got)
		})
	}
}
