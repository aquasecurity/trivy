package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rootio"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestProvider(t *testing.T) {
	tests := []struct {
		name    string
		libType ftypes.LangType
		pkgs    []ftypes.Package
		want    bool // true if driver should be returned, false if nil
	}{
		{
			name:    "Python packages with rootio version",
			libType: ftypes.Pip,
			pkgs: []ftypes.Package{
				{Name: "requests", Version: "2.28.1"},
				{Name: "django", Version: "4.0.1+root.io.1"},
			},
			want: true,
		},
		{
			name:    "Ruby packages with rootio version",
			libType: ftypes.GemSpec,
			pkgs: []ftypes.Package{
				{Name: "rails", Version: "7.0.1"},
				{Name: "puma", Version: "5.6.4+root.io.1"},
			},
			want: true,
		},
		{
			name:    "Node packages with rootio version",
			libType: ftypes.Npm,
			pkgs: []ftypes.Package{
				{Name: "express", Version: "4.18.1"},
				{Name: "lodash", Version: "4.17.21+root.io.1"},
			},
			want: true,
		},
		{
			name:    "Python packages without rootio version",
			libType: ftypes.Pip,
			pkgs: []ftypes.Package{
				{Name: "requests", Version: "2.28.1"},
				{Name: "django", Version: "4.0.1"},
			},
			want: false,
		},
		{
			name:    "Unsupported language type",
			libType: ftypes.Julia,
			pkgs: []ftypes.Package{
				{Name: "DataFrames", Version: "1.3.4+root.io.1"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := rootio.Provider(tt.libType, tt.pkgs)
			if tt.want {
				require.NotNil(t, driver, "Provider should return a driver for Root.io environment")
			} else {
				assert.Nil(t, driver, "Provider should return nil for non-Root.io environment")
			}
		})
	}
}

func TestIsRootIOEnvironment(t *testing.T) {
	tests := []struct {
		name string
		pkgs []ftypes.Package
		want bool
	}{
		{
			name: "Package with +root.io suffix",
			pkgs: []ftypes.Package{
				{Name: "package1", Version: "1.2.3"},
				{Name: "package2", Version: "2.0.0+root.io.1"},
			},
			want: true,
		},
		{
			name: "Multiple packages with root.io suffix",
			pkgs: []ftypes.Package{
				{Name: "package1", Version: "1.2.3+root.io.1"},
				{Name: "package2", Version: "2.0.0+root.io.2"},
			},
			want: true,
		},
		{
			name: "No packages with root.io suffix",
			pkgs: []ftypes.Package{
				{Name: "package1", Version: "1.2.3"},
				{Name: "package2", Version: "2.0.0"},
			},
			want: false,
		},
		{
			name: "Package with root.io in name but not version",
			pkgs: []ftypes.Package{
				{Name: "root.io-client", Version: "1.2.3"},
				{Name: "package2", Version: "2.0.0"},
			},
			want: false,
		},
		{
			name: "Empty package list",
			pkgs: []ftypes.Package{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRootIOEnvironment(tt.pkgs)
			assert.Equal(t, tt.want, got)
		})
	}
}
