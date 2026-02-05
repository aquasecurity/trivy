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

// Detector detects OS package vulnerabilities.
type Detector struct {
	target types.ScanTarget
	driver driver.Driver
}

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

// NewDetector creates a new Detector for the given scan target
func NewDetector(target types.ScanTarget) (*Detector, error) {
	drv, err := newDriver(target.OS.Family, target.Packages)
	if err != nil {
		return nil, err
	}
	return &Detector{
		target: target,
		driver: drv,
	}, nil
}

// Detect detects the vulnerabilities
func (d *Detector) Detect(ctx context.Context) ([]types.DetectedVulnerability, bool, error) {
	ctx = log.WithContextPrefix(ctx, string(d.target.OS.Family))

	eosl := !d.driver.IsSupportedVersion(ctx, d.target.OS.Family, d.target.OS.Name)

	filteredPkgs := filterPkgs(ctx, d.target.Packages)
	vulns, err := d.driver.Detect(ctx, d.target.OS.Name, d.target.Repository, filteredPkgs)
	if err != nil {
		return nil, false, xerrors.Errorf("failed detection: %w", err)
	}

	return vulns, eosl, nil
}

// filterPkgs filters out packages that should not be scanned:
//   - gpg-pubkey: doesn't use the correct version
//   - Third-party packages: not covered by official OS security advisories
func filterPkgs(ctx context.Context, pkgs []ftypes.Package) []ftypes.Package {
	var skipped []string
	filtered := lo.Filter(pkgs, func(pkg ftypes.Package, _ int) bool {
		if pkg.Name == "gpg-pubkey" {
			return false
		}
		if pkg.Repository.Class == ftypes.RepositoryClassThirdParty {
			skipped = append(skipped, pkg.Name)
			return false
		}
		return true
	})
	if len(skipped) > 0 {
		log.DebugContext(ctx, "Skipping third-party packages", log.Any("packages", skipped))
	}
	return filtered
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
