package ospkg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type mockDriver struct {
	called bool
	// receivedPkgs are the packages passed to Detect.
	receivedPkgs []ftypes.Package
	// filteredPkgs are the packages passed to FilterPackages.
	filteredPkgs []ftypes.Package
	// filter narrows the package set. A nil filter keeps everything.
	filter func([]ftypes.Package) []ftypes.Package
}

func (m *mockDriver) FilterPackages(_ context.Context, pkgs []ftypes.Package) []ftypes.Package {
	m.filteredPkgs = pkgs
	if m.filter == nil {
		return pkgs
	}
	return m.filter(pkgs)
}

func (m *mockDriver) Detect(_ context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	m.called = true
	m.receivedPkgs = pkgs
	return nil, nil
}

func (m *mockDriver) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

func TestDetector_Detect(t *testing.T) {
	official := ftypes.Package{
		Name: "vim",
		Repository: ftypes.PackageRepository{
			Class: ftypes.RepositoryClassOfficial,
		},
	}
	thirdParty := ftypes.Package{
		Name: "php",
		Repository: ftypes.PackageRepository{
			Class: ftypes.RepositoryClassThirdParty,
		},
	}

	tests := []struct {
		name string
		pkgs []ftypes.Package
		// filter is the driver's own FilterPackages. A nil filter keeps everything.
		filter func([]ftypes.Package) []ftypes.Package
		// wantFiltered are the packages the driver's filter must be given.
		wantFiltered []ftypes.Package
		// wantDetected are the packages Detect must be given.
		wantDetected []ftypes.Package
	}{
		{
			// The detector drops gpg-pubkey itself, before the driver has a say,
			// because it carries no real version for any driver to match.
			name:         "gpg-pubkey is dropped before the driver filter",
			pkgs:         []ftypes.Package{official, {Name: "gpg-pubkey"}},
			wantFiltered: []ftypes.Package{official},
			wantDetected: []ftypes.Package{official},
		},
		{
			name:         "a driver that keeps everything receives every package",
			pkgs:         []ftypes.Package{official, thirdParty},
			wantFiltered: []ftypes.Package{official, thirdParty},
			wantDetected: []ftypes.Package{official, thirdParty},
		},
		{
			name: "the driver filter decides what Detect receives",
			pkgs: []ftypes.Package{official, thirdParty},
			filter: func(pkgs []ftypes.Package) []ftypes.Package {
				return driver.DropThirdPartyPackages(t.Context(), pkgs)
			},
			wantFiltered: []ftypes.Package{official, thirdParty},
			wantDetected: []ftypes.Package{official},
		},
		{
			name:         "no packages",
			pkgs:         nil,
			wantFiltered: []ftypes.Package{},
			wantDetected: []ftypes.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := types.ScanTarget{
				OS: ftypes.OS{
					Family: ftypes.CentOS,
					Name:   "7",
				},
				Packages: tt.pkgs,
			}
			mockDrv := &mockDriver{filter: tt.filter}
			d, err := ospkg.NewDetector(target, ospkg.WithDriver(target.OS.Family, mockDrv))
			require.NoError(t, err)

			_, _, err = d.Detect(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tt.wantFiltered, mockDrv.filteredPkgs)
			assert.Equal(t, tt.wantDetected, mockDrv.receivedPkgs)
		})
	}
}

func TestNewDetector(t *testing.T) {
	target := types.ScanTarget{
		OS: ftypes.OS{
			Family: ftypes.CentOS,
			Name:   "7",
		},
		Packages: []ftypes.Package{{Name: "vim"}},
	}

	tests := []struct {
		name       string
		target     types.ScanTarget
		drivers    map[ftypes.OSType]string // OS family => driver name
		providers  []string                 // driver names returned by providers, in registration order
		wantCalled string                   // name of the driver expected to handle detection
		wantErr    string
	}{
		{
			name:       "provider takes priority over driver",
			target:     target,
			drivers:    map[ftypes.OSType]string{ftypes.CentOS: "driver"},
			providers:  []string{"provider"},
			wantCalled: "provider",
		},
		{
			name:       "most recently registered provider is tried first",
			target:     target,
			providers:  []string{"first", "second"},
			wantCalled: "second",
		},
		{
			name:    "unsupported OS returns error",
			target:  types.ScanTarget{OS: ftypes.OS{Family: "unknown-os"}},
			wantErr: "unsupported os",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a named mock driver and track it for assertions.
			mocks := make(map[string]*mockDriver)
			mock := func(name string) *mockDriver {
				m := &mockDriver{}
				mocks[name] = m
				return m
			}

			var opts []ospkg.Option
			for family, name := range tt.drivers {
				opts = append(opts, ospkg.WithDriver(family, mock(name)))
			}
			for _, name := range tt.providers {
				drv := mock(name)
				opts = append(opts, ospkg.WithProvider(func(_ ftypes.OSType, _ []ftypes.Package) driver.Driver {
					return drv
				}))
			}

			d, err := ospkg.NewDetector(tt.target, opts...)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			_, _, err = d.Detect(t.Context())
			require.NoError(t, err)

			for name, m := range mocks {
				if name == tt.wantCalled {
					assert.Truef(t, m.called, "driver %q should have been used for detection", name)
				} else {
					assert.Falsef(t, m.called, "driver %q should not have been used for detection", name)
				}
			}
		})
	}
}
