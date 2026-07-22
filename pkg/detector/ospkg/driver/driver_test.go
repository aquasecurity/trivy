package driver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestDropThirdPartyPackages(t *testing.T) {
	pkg := func(name string, class ftypes.RepositoryClass) ftypes.Package {
		return ftypes.Package{
			Name: name,
			Repository: ftypes.PackageRepository{
				Class: class,
			},
		}
	}

	official := pkg("vim", ftypes.RepositoryClassOfficial)
	thirdParty := pkg("php", ftypes.RepositoryClassThirdParty)
	unknown := pkg("curl", ftypes.RepositoryClassUnknown)
	// A package the analyzer never classified, e.g. from the apk analyzer.
	unclassified := ftypes.Package{Name: "musl"}

	tests := []struct {
		name string
		pkgs []ftypes.Package
		want []ftypes.Package
	}{
		{
			name: "package from a third-party repository is dropped",
			pkgs: []ftypes.Package{thirdParty},
			want: []ftypes.Package{},
		},
		{
			name: "package from an official repository is kept",
			pkgs: []ftypes.Package{official},
			want: []ftypes.Package{official},
		},
		{
			name: "package with an unknown repository class is kept",
			pkgs: []ftypes.Package{unknown},
			want: []ftypes.Package{unknown},
		},
		{
			// Only RepositoryClassThirdParty is dropped, so an analyzer that does not
			// set the class at all keeps its packages.
			name: "package without a repository class is kept",
			pkgs: []ftypes.Package{unclassified},
			want: []ftypes.Package{unclassified},
		},
		{
			name: "the remaining packages keep their order",
			pkgs: []ftypes.Package{official, thirdParty, unknown, unclassified},
			want: []ftypes.Package{official, unknown, unclassified},
		},
		{
			name: "every package is third-party",
			pkgs: []ftypes.Package{thirdParty, pkg("nginx", ftypes.RepositoryClassThirdParty)},
			want: []ftypes.Package{},
		},
		{
			name: "no packages",
			pkgs: nil,
			want: []ftypes.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, driver.DropThirdPartyPackages(t.Context(), tt.pkgs))
		})
	}
}
