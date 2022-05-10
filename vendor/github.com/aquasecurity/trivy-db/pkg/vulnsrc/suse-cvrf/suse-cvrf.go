package susecvrf

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type Distribution int

const (
	SUSEEnterpriseLinux Distribution = iota
	OpenSUSE

	platformOpenSUSEFormat  = "openSUSE Leap %s"
	platformSUSELinuxFormat = "SUSE Linux Enterprise %s"
)

var (
	suseDir = filepath.Join("cvrf", "suse")

	versionReplacer = strings.NewReplacer("-SECURITY", "", "-LTSS", "", "-TERADATA", "")

	source = types.DataSource{
		ID:   vulnerability.SuseCVRF,
		Name: "SUSE CVRF",
		URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
	}
)

type VulnSrc struct {
	dist Distribution
	dbc  db.Operation
}

func NewVulnSrc(dist Distribution) VulnSrc {
	return VulnSrc{
		dist: dist,
		dbc:  db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	log.Println("Saving SUSE CVRF")

	rootDir := filepath.Join(dir, "vuln-list", suseDir)
	switch vs.dist {
	case SUSEEnterpriseLinux:
		rootDir = filepath.Join(rootDir, "suse")
	case OpenSUSE:
		rootDir = filepath.Join(rootDir, "opensuse")
	default:
		return xerrors.New("unknown distribution")
	}

	var cvrfs []SuseCvrf
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cvrf SuseCvrf
		if err := json.NewDecoder(r).Decode(&cvrf); err != nil {
			return xerrors.Errorf("failed to decode SUSE CVRF JSON: %w %+v", err, cvrf)
		}
		cvrfs = append(cvrfs, cvrf)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in SUSE CVRF walk: %w", err)
	}

	if err = vs.save(cvrfs); err != nil {
		return xerrors.Errorf("error in SUSE CVRF save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cvrfs []SuseCvrf) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cvrfs []SuseCvrf) error {
	for _, cvrf := range cvrfs {
		affectedPkgs := getAffectedPackages(cvrf.ProductTree.Relationships)
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, affectedPkg := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: affectedPkg.Package.FixedVersion,
			}

			if err := vs.dbc.PutDataSource(tx, affectedPkg.OSVer, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, cvrf.Tracking.ID, affectedPkg.Package.Name,
				[]string{affectedPkg.OSVer}, advisory); err != nil {
				return xerrors.Errorf("unable to save %s CVRF: %w", affectedPkg.OSVer, err)
			}
		}

		var references []string
		for _, ref := range cvrf.References {
			references = append(references, ref.URL)
		}

		severity := types.SeverityUnknown
		for _, cvuln := range cvrf.Vulnerabilities {
			for _, threat := range cvuln.Threats {
				sev := severityFromThreat(threat.Severity)
				if severity < sev {
					severity = sev
				}
			}
		}

		vuln := types.VulnerabilityDetail{
			References:  references,
			Title:       cvrf.Title,
			Description: getDetail(cvrf.Notes),
			Severity:    severity,
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, cvrf.Tracking.ID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save SUSE CVRF vulnerability: %w", err)
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cvrf.Tracking.ID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}
	return nil
}

func getAffectedPackages(relationships []Relationship) []AffectedPackage {
	var pkgs []AffectedPackage
	for _, relationship := range relationships {
		osVer := getOSVersion(relationship.RelatesToProductReference)
		if osVer == "" {
			continue
		}

		pkg := getPackage(relationship.ProductReference)
		if pkg == nil {
			log.Printf("invalid package name: %s", relationship.ProductReference)
			continue
		}

		pkgs = append(pkgs, AffectedPackage{
			OSVer:   osVer,
			Package: *pkg,
		})
	}

	return pkgs
}

func getOSVersion(platformName string) string {
	if strings.Contains(platformName, "SUSE Manager") {
		// SUSE Linux Enterprise Module for SUSE Manager Server 4.0
		return ""
	}
	if strings.HasPrefix(platformName, "openSUSE Leap") {
		// openSUSE Leap 15.0
		ss := strings.Split(platformName, " ")
		if len(ss) < 3 {
			log.Printf("invalid version: %s", platformName)
			return ""
		}
		if _, err := version.NewVersion(ss[2]); err != nil {
			log.Printf("invalid version: %s, err: %s", platformName, err)
			return ""
		}
		return fmt.Sprintf(platformOpenSUSEFormat, ss[2])
	}
	if strings.Contains(platformName, "SUSE Linux Enterprise") {
		// e.g. SUSE Linux Enterprise Server 12 SP1-LTSS
		ss := strings.Fields(platformName)
		if strings.HasPrefix(ss[len(ss)-1], "SP") || ustrings.IsInt(ss[len(ss)-2]) {
			// Remove suffix such as -TERADATA, -LTSS
			sps := strings.Split(ss[len(ss)-1], "-")
			// Remove "SP" prefix
			sp := strings.TrimPrefix(sps[0], "SP")
			// Check if the version is integer
			spVersion, err := strconv.Atoi(sp)
			if err != nil {
				log.Printf("invalid SP version: %s, err: %s", platformName, err)
				return ""
			}
			osVer := fmt.Sprintf("%s.%d", ss[len(ss)-2], spVersion)
			return fmt.Sprintf(platformSUSELinuxFormat, osVer)
		} else {
			// e.g. SUSE Linux Enterprise Server 11-SECURITY
			ver := versionReplacer.Replace(ss[len(ss)-1])
			if _, err := version.NewVersion(ver); err != nil {
				log.Printf("invalid OS version: %s, err: %s", platformName, err)
				return ""
			}
			return fmt.Sprintf(platformSUSELinuxFormat, ver)
		}
	}

	return ""
}

func getDetail(notes []DocumentNote) string {
	for _, n := range notes {
		if n.Type == "General" && n.Title == "Details" {
			return n.Text
		}
	}
	return ""
}

func getPackage(packVer string) *Package {
	name, version := splitPkgName(packVer)
	return &Package{
		Name:         name,
		FixedVersion: version,
	}
}

// reference: https://github.com/aquasecurity/trivy-db/blob/5c844be3ba6b9ef13df640857a10f8737e360feb/pkg/vulnsrc/redhat/redhat.go#L196-L217
func splitPkgName(pkgName string) (string, string) {
	var version string

	// Trim release
	index := strings.LastIndex(pkgName, "-")
	if index == -1 {
		return "", ""
	}
	version = pkgName[index:]
	pkgName = pkgName[:index]

	// Trim version
	index = strings.LastIndex(pkgName, "-")
	if index == -1 {
		return "", ""
	}
	version = pkgName[index+1:] + version
	pkgName = pkgName[:index]

	return pkgName, version
}

func (vs VulnSrc) Get(version string, pkgName string) ([]types.Advisory, error) {
	var bucket string
	switch vs.dist {
	case SUSEEnterpriseLinux:
		bucket = fmt.Sprintf(platformSUSELinuxFormat, version)
	case OpenSUSE:
		bucket = fmt.Sprintf(platformOpenSUSEFormat, version)
	default:
		return nil, xerrors.New("unknown distribution")
	}

	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get SUSE advisories: %w", err)
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
