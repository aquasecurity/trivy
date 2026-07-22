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
}

func (m *mockDriver) Detect(_ context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	m.called = true
	m.receivedPkgs = pkgs
	return nil, nil
}

func (m *mockDriver) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

// filteringMockDriver implements the optional package filter, so the detector uses it
// instead of the default third-party filter.
type filteringMockDriver struct {
	*mockDriver
	filter func([]ftypes.Package) []ftypes.Package
}

func (m *filteringMockDriver) FilterPackages(_ context.Context, pkgs []ftypes.Package) []ftypes.Package {
	return m.filter(pkgs)
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
		// filter is the driver's optional FilterPackages. A nil filter means the driver
		// does not implement it, so the detector applies the default third-party filter.
		filter func([]ftypes.Package) []ftypes.Package
		// wantDetected are the packages Detect must be given.
		wantDetected []ftypes.Package
	}{
		{
			// A plain driver gets the default: gpg-pubkey and third-party packages go.
			name:         "default driver drops gpg-pubkey and third-party packages",
			pkgs:         []ftypes.Package{official, {Name: "gpg-pubkey"}, thirdParty},
			wantDetected: []ftypes.Package{official},
		},
		{
			// A driver that keeps everything still never sees gpg-pubkey: the detector
			// drops it before handing the set to the driver's filter.
			name:         "filtering driver keeps third-party packages but not gpg-pubkey",
			pkgs:         []ftypes.Package{official, {Name: "gpg-pubkey"}, thirdParty},
			filter:       func(pkgs []ftypes.Package) []ftypes.Package { return pkgs },
			wantDetected: []ftypes.Package{official, thirdParty},
		},
		{
			name:         "no packages",
			pkgs:         nil,
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
			base := &mockDriver{}
			var drv driver.Driver = base
			if tt.filter != nil {
				drv = &filteringMockDriver{mockDriver: base, filter: tt.filter}
			}
			d, err := ospkg.NewDetector(target, ospkg.WithDriver(target.OS.Family, drv))
			require.NoError(t, err)

			_, _, err = d.Detect(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tt.wantDetected, base.receivedPkgs)
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

// TestDriversPackageFilter checks which registered drivers override the default filter.
// Only drivers whose own advisories describe third-party packages should, so that a
// curated-feed driver that forgets the override (and would silently drop those packages)
// is caught here.
func TestDriversPackageFilter(t *testing.T) {
	// Registered drivers that keep third-party packages. Provider-built drivers
	// (Root.io, Seal) are not registered and have their own tests.
	keepsThirdPartyPackages := map[ftypes.OSType]bool{
		ftypes.Echo: true,
	}

	for family, drv := range ospkg.Drivers() {
		t.Run(string(family), func(t *testing.T) {
			_, ok := drv.(driver.PackageFilter)
			assert.Equal(t, keepsThirdPartyPackages[family], ok,
				"%s: whether it overrides the default third-party filter", family)
		})
	}
}
