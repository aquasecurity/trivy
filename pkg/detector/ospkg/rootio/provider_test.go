package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestProvider(t *testing.T) {
	tests := []struct {
		name     string
		osFamily ftypes.OSType
		pkgs     []ftypes.Package
		want     bool // true if driver should be returned, false if nil
	}{
		{
			name:     "Debian with root.io package",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-13+deb11u4root.io"},
				{Name: "bash", Version: "5.1-2+deb11u1"},
			},
			want: true,
		},
		{
			name:     "Ubuntu with root.io package",
			osFamily: ftypes.Ubuntu,
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-0ubuntu9.9root.io"},
				{Name: "bash", Version: "5.1-6ubuntu1"},
			},
			want: true,
		},
		{
			name:     "Alpine with roo7 package",
			osFamily: ftypes.Alpine,
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3-r0roo7"},
				{Name: "busybox", Version: "1.35.0-r17"},
			},
			want: true,
		},
		{
			name:     "Debian without root.io package",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-13+deb11u4"},
				{Name: "bash", Version: "5.1-2+deb11u1"},
			},
			want: false,
		},
		{
			name:     "Ubuntu without root.io package",
			osFamily: ftypes.Ubuntu,
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-0ubuntu9.9"},
				{Name: "bash", Version: "5.1-6ubuntu1"},
			},
			want: false,
		},
		{
			name:     "Alpine without roo7 package",
			osFamily: ftypes.Alpine,
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3-r0"},
				{Name: "busybox", Version: "1.35.0-r17"},
			},
			want: false,
		},
		{
			name:     "Unsupported OS family",
			osFamily: ftypes.RedHat,
			pkgs: []ftypes.Package{
				{Name: "glibc", Version: "2.28-151.el8root.io"},
			},
			want: false,
		},
		{
			name:     "Empty package list",
			osFamily: ftypes.Debian,
			pkgs:     []ftypes.Package{},
			want:     false,
		},
		{
			name:     "Multiple root.io packages",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-13+deb11u4root.io"},
				{Name: "openssl", Version: "1.1.1n-0+deb11u3root.io"},
			},
			want: true,
		},
		{
			name:     "Multiple roo7 packages",
			osFamily: ftypes.Alpine,
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3-r0roo7"},
				{Name: "openssl", Version: "1.1.1t-r0roo7"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := Provider(tt.osFamily, tt.pkgs)
			if tt.want {
				require.NotNil(t, driver, "Provider should return a driver for Root.io environment")
				// Verify it's actually a Root.io scanner
				scanner, ok := driver.(*Scanner)
				assert.True(t, ok, "Driver should be of type *Scanner")
				assert.Equal(t, tt.osFamily, scanner.baseOS, "Scanner should have correct base OS")
			} else {
				assert.Nil(t, driver, "Provider should return nil for non-Root.io environment")
			}
		})
	}
}

func TestIsRootIOEnvironment(t *testing.T) {
	tests := []struct {
		name     string
		osFamily ftypes.OSType
		pkgs     []ftypes.Package
		want     bool
	}{
		{
			name:     "Debian with root.io suffix",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0root.io"},
			},
			want: true,
		},
		{
			name:     "Ubuntu with root.io suffix",
			osFamily: ftypes.Ubuntu,
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0root.io"},
			},
			want: true,
		},
		{
			name:     "Alpine with roo7 suffix",
			osFamily: ftypes.Alpine,
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0roo7"},
			},
			want: true,
		},
		{
			name:     "Root.io in middle of version string",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0root.io.1"},
			},
			want: true,
		},
		{
			name:     "Multiple packages, one with root.io",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "normal-pkg", Version: "1.0.0"},
				{Name: "patched-pkg", Version: "2.0.0root.io"},
			},
			want: true,
		},
		{
			name:     "No root.io packages",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "normal-pkg", Version: "1.0.0"},
			},
			want: false,
		},
		{
			name:     "Unsupported OS type with root.io",
			osFamily: ftypes.RedHat,
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0root.io"},
			},
			want: false,
		},
		{
			name:     "Empty package list",
			osFamily: ftypes.Debian,
			pkgs:     []ftypes.Package{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRootIOEnvironment(tt.osFamily, tt.pkgs)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasPackageWithSuffix(t *testing.T) {
	tests := []struct {
		name   string
		pkgs   []ftypes.Package
		suffix string
		want   bool
	}{
		{
			name: "Package with exact suffix",
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0root.io"},
			},
			suffix: "root.io",
			want:   true,
		},
		{
			name: "Package with suffix in middle",
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0root.io.1"},
			},
			suffix: "root.io",
			want:   true,
		},
		{
			name: "Multiple packages, one matches",
			pkgs: []ftypes.Package{
				{Name: "normal-pkg", Version: "1.0.0"},
				{Name: "patched-pkg", Version: "2.0.0roo7"},
			},
			suffix: "roo7",
			want:   true,
		},
		{
			name: "No packages match",
			pkgs: []ftypes.Package{
				{Name: "normal-pkg", Version: "1.0.0"},
				{Name: "another-pkg", Version: "2.0.0"},
			},
			suffix: "root.io",
			want:   false,
		},
		{
			name:   "Empty package list",
			pkgs:   []ftypes.Package{},
			suffix: "root.io",
			want:   false,
		},
		{
			name: "Empty suffix",
			pkgs: []ftypes.Package{
				{Name: "test-pkg", Version: "1.0.0"},
			},
			suffix: "",
			want:   true, // Empty string is contained in any string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasPackageWithSuffix(tt.pkgs, tt.suffix)
			assert.Equal(t, tt.want, got)
		})
	}
}