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
	called       bool
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

// mockThirdPartyDriver implements both Driver and driver.ThirdPartyAware.
// It is used to verify that filterPkgs still drops gpg-pubkey even when the
// driver opts to receive third-party packages.
type mockThirdPartyDriver struct {
	mockDriver
}

func (m *mockThirdPartyDriver) IncludesThirdParty() bool {
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
			d, err := ospkg.NewDetector(tt.target, ospkg.WithDriver(tt.target.OS.Family, mockDrv))
			require.NoError(t, err)

			_, _, err = d.Detect(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, mockDrv.receivedPkgs)
		})
	}
}

// TestDetector_Detect_ThirdPartyAware verifies that when the driver opts in via
// ThirdPartyAware, third-party packages reach Detect but gpg-pubkey is still
// filtered out (gpg-pubkey has no scannable version and is dropped for every
// driver regardless of the opt-in).
func TestDetector_Detect_ThirdPartyAware(t *testing.T) {
	target := types.ScanTarget{
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
	}

	// Expected: gpg-pubkey stripped; the third-party php package passes through
	// because the driver opted in.
	wantPkgs := []ftypes.Package{
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
	}

	mockDrv := &mockThirdPartyDriver{}
	d, err := ospkg.NewDetector(target, ospkg.WithDriver(target.OS.Family, mockDrv))
	require.NoError(t, err)

	_, _, err = d.Detect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, wantPkgs, mockDrv.receivedPkgs)
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
