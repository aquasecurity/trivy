package ospkg

import (
	"context"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alma"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alpine"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/amazon"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/azure"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/bottlerocket"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/chainguard"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/coreos"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/echo"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/minimos"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/oracle"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/photon"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/redhat"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rocky"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rootio"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/seal"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/suse"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/ubuntu"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/wolfi"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	// ErrUnsupportedOS defines error for unsupported OS
	ErrUnsupportedOS = xerrors.New("unsupported os")

	drivers = map[ftypes.OSType]driver.Driver{
		ftypes.Alpine:             alpine.NewScanner(),
		ftypes.Alma:               alma.NewScanner(),
		ftypes.Amazon:             amazon.NewScanner(),
		ftypes.Azure:              azure.NewAzureScanner(),
		ftypes.Bottlerocket:       bottlerocket.NewScanner(),
		ftypes.CBLMariner:         azure.NewMarinerScanner(),
		ftypes.Debian:             debian.NewScanner(),
		ftypes.Ubuntu:             ubuntu.NewScanner(),
		ftypes.RedHat:             redhat.NewScanner(),
		ftypes.CentOS:             redhat.NewScanner(),
		ftypes.Rocky:              rocky.NewScanner(),
		ftypes.Oracle:             oracle.NewScanner(),
		ftypes.OpenSUSETumbleweed: suse.NewScanner(suse.OpenSUSETumbleweed),
		ftypes.OpenSUSELeap:       suse.NewScanner(suse.OpenSUSE),
		ftypes.SLES:               suse.NewScanner(suse.SUSEEnterpriseLinux),
		ftypes.SLEMicro:           suse.NewScanner(suse.SUSEEnterpriseLinuxMicro),
		ftypes.Photon:             photon.NewScanner(),
		ftypes.Wolfi:              wolfi.NewScanner(),
		ftypes.Chainguard:         chainguard.NewScanner(),
		ftypes.Echo:               echo.NewScanner(),
		ftypes.MinimOS:            minimos.NewScanner(),
		ftypes.CoreOS:             coreos.NewScanner(),
	}

	// providers dynamically generate drivers based on package information
	// and environment detection. They are tried before standard OS-specific drivers.
	providers = []driver.Provider{
		rootio.Provider,
		seal.Provider,
	}
)

// RegisterDriver is defined for extensibility and not supposed to be used in Trivy.
func RegisterDriver(name ftypes.OSType, drv driver.Driver) {
	drivers[name] = drv
}

// Detect detects the vulnerabilities
func Detect(ctx context.Context, target types.ScanTarget, _ types.ScanOptions) ([]types.DetectedVulnerability, bool, error) {
	ctx = log.WithContextPrefix(ctx, string(target.OS.Family))

	d, err := newDriver(target.OS.Family, target.Packages)
	if err != nil {
		return nil, false, ErrUnsupportedOS
	}

	eosl := !d.IsSupportedVersion(ctx, target.OS.Family, target.OS.Name)

	// Package `gpg-pubkey` doesn't use the correct version.
	// We don't need to find vulnerabilities for this package.
	filteredPkgs := lo.Filter(target.Packages, func(pkg ftypes.Package, _ int) bool {
		return pkg.Name != "gpg-pubkey"
	})
	vulns, err := d.Detect(ctx, target.OS.Name, target.Repository, filteredPkgs)
	if err != nil {
		return nil, false, xerrors.Errorf("failed detection: %w", err)
	}

	return vulns, eosl, nil
}

func newDriver(osFamily ftypes.OSType, pkgs []ftypes.Package) (driver.Driver, error) {
	// Try providers first
	for _, provider := range providers {
		if d := provider(osFamily, pkgs); d != nil {
			return d, nil
		}
	}

	// Fall back to standard drivers
	if d, ok := drivers[osFamily]; ok {
		return d, nil
	}

	log.Warn("Unsupported os", log.String("family", string(osFamily)))
	return nil, ErrUnsupportedOS
}
