package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestProvider(t *testing.T) {
	tests := []struct {
		name     string
		libType  ftypes.LangType
		pkgs     []ftypes.Package
		wantType string
	}{
		{
			name:    "Python packages with rootio version",
			libType: ftypes.Pip,
			pkgs: []ftypes.Package{
				{Name: "requests", Version: "2.28.1"},
				{Name: "django", Version: "4.0.1.root.io"},
			},
			wantType: "pip",
		},
		{
			name:    "Ruby packages with rootio version",
			libType: ftypes.GemSpec,
			pkgs: []ftypes.Package{
				{Name: "rails", Version: "7.0.1"},
				{Name: "puma", Version: "5.6.4.root.io"},
			},
			wantType: "rubygems",
		},
		{
			name:    "Node packages with rootio version",
			libType: ftypes.Npm,
			pkgs: []ftypes.Package{
				{Name: "express", Version: "4.18.1"},
				{Name: "lodash", Version: "4.17.21.root.io"},
			},
			wantType: "npm",
		},
		{
			name:    "Python packages without rootio version",
			libType: ftypes.Pip,
			pkgs: []ftypes.Package{
				{Name: "requests", Version: "2.28.1"},
				{Name: "django", Version: "4.0.1"},
			},
			wantType: "",
		},
		{
			name:    "Unsupported language type",
			libType: ftypes.Julia,
			pkgs: []ftypes.Package{
				{Name: "DataFrames", Version: "1.3.4.root.io"},
			},
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Provider(tt.libType, tt.pkgs)
			if tt.wantType == "" {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				if driver, ok := result.(*Scanner); ok {
					assert.Equal(t, tt.wantType, driver.Type())
				} else {
					t.Errorf("Expected *Scanner type, got %T", result)
				}
			}
		})
	}
}

func TestGetEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		libType   ftypes.LangType
		wantEco   dbTypes.Ecosystem
		wantFound bool
	}{
		{
			name:      "Python Pip",
			libType:   ftypes.Pip,
			wantEco:   vulnerability.Pip,
			wantFound: true,
		},
		{
			name:      "Ruby Bundler",
			libType:   ftypes.Bundler,
			wantEco:   vulnerability.RubyGems,
			wantFound: true,
		},
		{
			name:      "Node NPM",
			libType:   ftypes.Npm,
			wantEco:   vulnerability.Npm,
			wantFound: true,
		},
		{
			name:      "Java Maven",
			libType:   ftypes.Jar,
			wantEco:   vulnerability.Maven,
			wantFound: true,
		},
		{
			name:      "Go Module",
			libType:   ftypes.GoModule,
			wantEco:   vulnerability.Go,
			wantFound: true,
		},
		{
			name:      "Unsupported Julia",
			libType:   ftypes.Julia,
			wantEco:   "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, found := getEcosystem(tt.libType)
			assert.Equal(t, tt.wantFound, found)
			if found {
				assert.Equal(t, tt.wantEco, eco)
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
			name: "Package with .root.io suffix",
			pkgs: []ftypes.Package{
				{Name: "package1", Version: "1.2.3"},
				{Name: "package2", Version: "2.0.0.root.io"},
			},
			want: true,
		},
		{
			name: "Multiple packages with .root.io suffix",
			pkgs: []ftypes.Package{
				{Name: "package1", Version: "1.2.3.root.io"},
				{Name: "package2", Version: "2.0.0.root.io"},
			},
			want: true,
		},
		{
			name: "No packages with .root.io suffix",
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