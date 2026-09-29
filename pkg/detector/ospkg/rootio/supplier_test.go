package rootio_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rootio"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestSupplier(t *testing.T) {
	tests := []struct {
		name string
		os   ftypes.OS
		pkgs []ftypes.Package
		want bool // true if driver should be returned, false if nil
	}{
		{
			name: "Debian with .root.io package",
			os:   ftypes.OS{Family: ftypes.Debian},
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31", Release: "13+deb11u4.root.io"},
				{Name: "bash", Version: "5.1-2+deb11u1"},
			},
			want: true,
		},
		{
			name: "Ubuntu with .root.io package",
			os:   ftypes.OS{Family: ftypes.Ubuntu},
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-0ubuntu9.9.root.io"},
				{Name: "bash", Version: "5.1-6ubuntu1"},
			},
			want: true,
		},
		{
			name: "Alpine with Root.io pattern package",
			os:   ftypes.OS{Family: ftypes.Alpine},
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3-r10071"},
				{Name: "busybox", Version: "1.35.0-r17"},
			},
			want: true,
		},
		{
			name: "Debian without .root.io package",
			os:   ftypes.OS{Family: ftypes.Debian},
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-13+deb11u4"},
				{Name: "bash", Version: "5.1-2+deb11u1"},
			},
			want: false,
		},
		{
			name: "Ubuntu without .root.io package",
			os:   ftypes.OS{Family: ftypes.Ubuntu},
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-0ubuntu9.9"},
				{Name: "bash", Version: "5.1-6ubuntu1"},
			},
			want: false,
		},
		{
			name: "Alpine without Root.io pattern package",
			os:   ftypes.OS{Family: ftypes.Alpine},
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3-r0"},
				{Name: "busybox", Version: "1.35.0-r17"},
			},
			want: false,
		},
		{
			name: "Unsupported OS family",
			os:   ftypes.OS{Family: ftypes.RedHat},
			pkgs: []ftypes.Package{
				{Name: "glibc", Version: "2.28-151.el8.root.io"},
			},
			want: false,
		},
		{
			name: "Empty package list",
			os:   ftypes.OS{Family: ftypes.Debian},
			pkgs: []ftypes.Package{},
			want: false,
		},
		{
			name: "Multiple .root.io packages",
			os:   ftypes.OS{Family: ftypes.Debian},
			pkgs: []ftypes.Package{
				{Name: "libc6", Version: "2.31-13+deb11u4.root.io"},
				{Name: "openssl", Version: "1.1.1n-0+deb11u3.root.io"},
			},
			want: true,
		},
		{
			name: "Multiple Alpine Root.io pattern packages",
			os:   ftypes.OS{Family: ftypes.Alpine},
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3-r20072"},
				{Name: "openssl", Version: "1.1.1t-r10071"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := rootio.Supplier(tt.os, tt.pkgs)
			if tt.want {
				require.NotNil(t, driver, "Supplier should return a driver for Root.io environment")
			} else {
				assert.Nil(t, driver, "Supplier should return nil for non-Root.io environment")
			}
		})
	}
}
