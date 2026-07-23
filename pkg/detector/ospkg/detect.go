package ospkg

import (
	"context"
	"maps"
	"slices"

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
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/cleanstart"
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
		ftypes.CleanStart:         cleanstart.NewScanner(),
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

// resolver holds the candidate drivers and providers and resolves one for a scan target.
type resolver struct {
	drivers   map[ftypes.OSType]driver.Driver
	providers []driver.Provider
}

// Option configures a Detector. Options are provided for extensibility by users
// of Trivy as a library and are not used within Trivy itself.
type Option func(*resolver)

// WithDriver registers a driver for the given OS family, overriding the default one.
func WithDriver(family ftypes.OSType, drv driver.Driver) Option {
	return func(r *resolver) {
		r.drivers[family] = drv
	}
}

// WithProvider registers an additional provider. It takes priority over the
// built-in providers and the standard OS-specific drivers. When called multiple
// times, the most recently registered provider is tried first.
func WithProvider(provider driver.Provider) Option {
	return func(r *resolver) {
		r.providers = slices.Insert(r.providers, 0, provider)
	}
}

// NewDetector creates a new Detector for the given scan target
func NewDetector(target types.ScanTarget, opts ...Option) (*Detector, error) {
	r := &resolver{
		drivers:   maps.Clone(drivers),
		providers: slices.Clone(providers),
	}
	for _, opt := range opts {
		opt(r)
	}

	drv, err := r.resolve(target.OS.Family, target.Packages)
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

	// gpg-pubkey does not carry a real version.
	// Matching it against any advisory is meaningless, for every driver.
	pkgs := lo.Filter(d.target.Packages, func(pkg ftypes.Package, _ int) bool {
		return pkg.Name != "gpg-pubkey"
	})

	// By default, drop packages installed from third-party repositories such as EPEL or
	// Docker: an OS vendor's advisories do not describe them. A driver whose own feed
	// covers those packages (Echo, Seal) implements packageFilter to keep them instead.
	filterFunc := driver.DropThirdPartyPackages
	if f, ok := d.driver.(driver.PackageFilter); ok {
		filterFunc = f.FilterPackages
	}

	vulns, err := d.driver.Detect(ctx, d.target.OS.Name, d.target.Repository, filterFunc(ctx, pkgs))
	if err != nil {
		return nil, false, xerrors.Errorf("failed detection: %w", err)
	}

	return vulns, eosl, nil
}

func (r *resolver) resolve(osFamily ftypes.OSType, pkgs []ftypes.Package) (driver.Driver, error) {
	// Try providers first
	for _, provider := range r.providers {
		if d := provider(osFamily, pkgs); d != nil {
			return d, nil
		}
	}

	// Fall back to standard drivers
	if d, ok := r.drivers[osFamily]; ok {
		return d, nil
	}

	log.Warn("Unsupported os", log.String("family", string(osFamily)))
	return nil, ErrUnsupportedOS
}
