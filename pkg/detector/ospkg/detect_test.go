package ospkg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type mockDriver struct {
	receivedPkgs []ftypes.Package
}

func (m *mockDriver) Detect(_ context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	m.receivedPkgs = pkgs
	return nil, nil
}

func (m *mockDriver) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

func TestDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		target   types.ScanTarget
		wantPkgs []ftypes.Package
	}{
		{
			name: "filter out gpg-pubkey package",
			target: types.ScanTarget{
				OS: ftypes.OS{
					Family: ftypes.CentOS,
					Name:   "7",
				},
				Packages: []ftypes.Package{
					{Name: "vim"},
					{Name: "gpg-pubkey"},
				},
			},
			wantPkgs: []ftypes.Package{
				{Name: "vim"},
			},
		},
		{
			name: "filter out third-party packages",
			target: types.ScanTarget{
				OS: ftypes.OS{
					Family: ftypes.CentOS,
					Name:   "7",
				},
				Packages: []ftypes.Package{
					{
						Name: "vim",
						Repository: ftypes.PackageRepository{
							Class: ftypes.RepositoryClassOfficial,
						},
					},
					{
						Name: "php",
						Repository: ftypes.PackageRepository{
							Class: ftypes.RepositoryClassThirdParty,
						},
					},
				},
			},
			wantPkgs: []ftypes.Package{
				{
					Name: "vim",
					Repository: ftypes.PackageRepository{
						Class: ftypes.RepositoryClassOfficial,
					},
				},
			},
		},
		{
			name: "filter out both gpg-pubkey and third-party packages",
			target: types.ScanTarget{
				OS: ftypes.OS{
					Family: ftypes.CentOS,
					Name:   "7",
				},
				Packages: []ftypes.Package{
					{
						Name: "vim",
						Repository: ftypes.PackageRepository{
							Class: ftypes.RepositoryClassOfficial,
						},
					},
					{Name: "gpg-pubkey"},
					{
						Name: "php",
						Repository: ftypes.PackageRepository{
							Class: ftypes.RepositoryClassThirdParty,
						},
					},
				},
			},
			wantPkgs: []ftypes.Package{
				{
					Name: "vim",
					Repository: ftypes.PackageRepository{
						Class: ftypes.RepositoryClassOfficial,
					},
				},
			},
		},
		{
			name: "keep packages with unknown repository class",
			target: types.ScanTarget{
				OS: ftypes.OS{
					Family: ftypes.CentOS,
					Name:   "7",
				},
				Packages: []ftypes.Package{
					{
						Name: "vim",
						Repository: ftypes.PackageRepository{
							Class: ftypes.RepositoryClassUnknown,
						},
					},
					{
						Name: "curl",
					},
				},
			},
			wantPkgs: []ftypes.Package{
				{
					Name: "vim",
					Repository: ftypes.PackageRepository{
						Class: ftypes.RepositoryClassUnknown,
					},
				},
				{
					Name: "curl",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDrv := &mockDriver{}
			d := ospkg.NewTestDetector(tt.target, mockDrv)

			_, _, err := d.Detect(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, mockDrv.receivedPkgs)
		})
	}
}
