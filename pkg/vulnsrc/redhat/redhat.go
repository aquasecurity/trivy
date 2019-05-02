package redhat

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/knqyf263/trivy/pkg/log"

	"github.com/knqyf263/trivy/pkg/db"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/utils"
)

const (
	redhatDir = "redhat"
)

var (
	platformFormat  = "Red Hat Enterprise Linux %d"
	targetPlatforms = []string{"Red Hat Enterprise Linux 5", "Red Hat Enterprise Linux 6", "Red Hat Enterprise Linux 7"}
	targetStatus    = []string{"Affected", "Fix deferred", "Will not fix"}
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, redhatDir)
	targets, err := utils.FilterTargets(redhatDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	}

	var cves []RedhatCVE
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		content, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		cve := RedhatCVE{}
		if err = json.Unmarshal(content, &cve); err != nil {
			return xerrors.Errorf("failed to decode RedHat JSON: %w", err)
		}
		switch cve.TempAffectedRelease.(type) {
		case []interface{}:
			var ar RedhatCVEAffectedReleaseArray
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = ar.AffectedRelease
		case map[string]interface{}:
			var ar RedhatCVEAffectedReleaseObject
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = []RedhatAffectedRelease{ar.AffectedRelease}
		case nil:
		default:
			return xerrors.New("unknown affected_release type")
		}

		switch cve.TempPackageState.(type) {
		case []interface{}:
			var ps RedhatCVEPackageStateArray
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = ps.PackageState
		case map[string]interface{}:
			var ps RedhatCVEPackageStateObject
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = []RedhatPackageState{ps.PackageState}
		case nil:
		default:
			return xerrors.New("unknown package_state type")
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in RedHat walk: %w", err)
	}

	if err = save(cves); err != nil {
		return xerrors.Errorf("error in RedHat save: %w", err)
	}

	return nil
}

// platformName: pkgStatus
type platform map[string]pkg

// pkgName: advisoryStatus
type pkg map[string]advisory

// cveID: version
type advisory map[string]interface{}

func save(cves []RedhatCVE) error {
	data := platform{}
	for _, cve := range cves {
		for _, affected := range cve.AffectedRelease {
			if affected.Package == "" {
				continue
			}
			// e.g. Red Hat Enterprise Linux 7
			platform := affected.ProductName
			if !utils.StringInSlice(affected.ProductName, targetPlatforms) {
				continue
			}

			pkgName, version := splitPkgName(affected.Package)
			p, ok := data[platform]
			if !ok {
				data[platform] = pkg{}
				p = data[platform]
			}

			a, ok := p[pkgName]
			if !ok {
				p[pkgName] = advisory{}
				a = p[pkgName]
			}

			a[cve.Name] = Advisory{
				CveID:     cve.Name,
				Version:   version,
				CvssScore: extractScore(cve.Cvss, cve.Cvss3),
			}
		}

		for _, pkgState := range cve.PackageState {
			pkgName := pkgState.PackageName
			if pkgName == "" {
				continue
			}
			// e.g. Red Hat Enterprise Linux 7
			platform := pkgState.ProductName
			if !utils.StringInSlice(platform, targetPlatforms) {
				continue
			}
			if !utils.StringInSlice(pkgState.FixState, targetStatus) {
				continue
			}

			p, ok := data[platform]
			if !ok {
				data[platform] = pkg{}
				p = data[platform]
			}

			a, ok := p[pkgName]
			if !ok {
				p[pkgName] = advisory{}
				a = p[pkgName]
			}

			a[cve.Name] = ""
			a[cve.Name] = Advisory{
				CveID: cve.Name,
				// this means all versions
				Version:   "",
				CvssScore: extractScore(cve.Cvss, cve.Cvss3),
			}
		}
	}

	log.Logger.Debug("Saving RedHat DB")
	for platform, pkgs := range data {
		bucketKV := map[string]map[string]interface{}{}
		for pkg, advisory := range pkgs {
			bucketKV[pkg] = map[string]interface{}(advisory)
		}
		if err := db.BatchUpdate(platform, bucketKV); err != nil {
			return xerrors.Errorf("error in db batch update: %w", err)
		}
	}
	return nil
}

func Get(majorVersion int, pkgName string) ([]Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, majorVersion)
	advisories, err := db.ForEach(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in RedHat foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []Advisory
	for _, v := range advisories {
		var advisory Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal RedHat JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

// ref. https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
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

func extractScore(cvss RedhatCvss, cvssv3 RedhatCvss3) float64 {
	score, err := strconv.ParseFloat(cvssv3.Cvss3BaseScore, 64)
	if err != nil {
		score, err = strconv.ParseFloat(cvss.CvssBaseScore, 64)
		if err != nil {
			return 0
		}
	}
	return score
}
