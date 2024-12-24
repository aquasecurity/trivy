package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	sp "github.com/aquasecurity/trivy-checks/pkg/spec"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Severity string

// ComplianceSpec represent the compliance specification
type ComplianceSpec struct {
	Spec iacTypes.Spec `yaml:"spec"`
}

const (
	FailStatus iacTypes.ControlStatus = "FAIL"
	PassStatus iacTypes.ControlStatus = "PASS"
	WarnStatus iacTypes.ControlStatus = "WARN"
)

// Scanners reads spec control and determines the scanners by check ID prefix
func (cs *ComplianceSpec) Scanners() (types.Scanners, error) {
	scannerTypes := set.New[types.Scanner]()
	for _, control := range cs.Spec.Controls {
		for _, check := range control.Checks {
			scannerType := scannerByCheckID(check.ID)
			if scannerType == types.UnknownScanner {
				return nil, xerrors.Errorf("unsupported check ID: %s", check.ID)
			}
			scannerTypes.Append(scannerType)
		}
	}
	return scannerTypes.Items(), nil
}

// CheckIDs return list of compliance check IDs
func (cs *ComplianceSpec) CheckIDs() map[types.Scanner][]string {
	checkIDsMap := make(map[types.Scanner][]string)
	for _, control := range cs.Spec.Controls {
		for _, check := range control.Checks {
			scannerType := scannerByCheckID(check.ID)
			checkIDsMap[scannerType] = append(checkIDsMap[scannerType], check.ID)
		}
	}
	return checkIDsMap
}

func scannerByCheckID(checkID string) types.Scanner {
	checkID = strings.ToLower(checkID)
	switch {
	case strings.HasPrefix(checkID, "cve-") || strings.HasPrefix(checkID, "dla-"):
		return types.VulnerabilityScanner
	case strings.HasPrefix(checkID, "avd-"):
		return types.MisconfigScanner
	case strings.HasPrefix(checkID, "vuln-"): // custom id for filtering vulnerabilities by severity
		return types.VulnerabilityScanner
	case strings.HasPrefix(checkID, "secret-"): // custom id for filtering secrets by severity
		return types.SecretScanner
	default:
		return types.UnknownScanner
	}
}

func checksDir(cacheDir string) string {
	return filepath.Join(cacheDir, "policy")
}

func complianceSpecDir(cacheDir string) string {
	return filepath.Join(checksDir(cacheDir), "content", "specs", "compliance")
}

// GetComplianceSpec accepct compliance flag name/path and return builtin or file system loaded spec
func GetComplianceSpec(specNameOrPath, cacheDir string) (ComplianceSpec, error) {
	if specNameOrPath == "" {
		return ComplianceSpec{}, nil
	}

	var b []byte
	var err error
	if strings.HasPrefix(specNameOrPath, "@") { // load user specified spec from disk
		b, err = os.ReadFile(strings.TrimPrefix(specNameOrPath, "@"))
		if err != nil {
			return ComplianceSpec{}, fmt.Errorf("error retrieving compliance spec from path: %w", err)
		}
		log.Debug("Compliance spec loaded from specified path", log.String("path", specNameOrPath))
	} else {
		_, err := os.Stat(filepath.Join(checksDir(cacheDir), "metadata.json"))
		if err != nil { // cache corrupt or bundle does not exist, load embedded version
			b = []byte(sp.NewSpecLoader().GetSpecByName(specNameOrPath))
			log.Debug("Compliance spec loaded from embedded library", log.String("spec", specNameOrPath))
		} else {
			// load from bundle on disk
			b, err = LoadFromBundle(cacheDir, specNameOrPath)
			if err != nil {
				return ComplianceSpec{}, err
			}
			log.Debug("Compliance spec loaded from disk bundle", log.String("spec", specNameOrPath))
		}
	}

	var complianceSpec ComplianceSpec
	if err = yaml.Unmarshal(b, &complianceSpec); err != nil {
		return ComplianceSpec{}, xerrors.Errorf("spec yaml decode error: %w", err)
	}
	return complianceSpec, nil

}

func LoadFromBundle(cacheDir, specNameOrPath string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(complianceSpecDir(cacheDir), specNameOrPath+".yaml"))
	if err != nil {
		return nil, fmt.Errorf("error retrieving compliance spec from bundle %s: %w", specNameOrPath, err)
	}
	return b, nil
}
