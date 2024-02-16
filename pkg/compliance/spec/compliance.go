package spec

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	sp "github.com/aquasecurity/trivy-policies/pkg/spec"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
	scannerTypes := make(map[types.Scanner]struct{})
	for _, control := range cs.Spec.Controls {
		for _, check := range control.Checks {
			scannerType := scannerByCheckID(check.ID)
			if scannerType == types.UnknownScanner {
				return nil, xerrors.Errorf("unsupported check ID: %s", check.ID)
			}
			scannerTypes[scannerType] = struct{}{}
		}
	}
	return maps.Keys(scannerTypes), nil
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

// GetComplianceSpec accepct compliance flag name/path and return builtin or file system loaded spec
func GetComplianceSpec(specNameOrPath string) (ComplianceSpec, error) {
	var b []byte
	var err error
	if strings.HasPrefix(specNameOrPath, "@") {
		b, err = os.ReadFile(strings.TrimPrefix(specNameOrPath, "@"))
		if err != nil {
			return ComplianceSpec{}, fmt.Errorf("error retrieving compliance spec from path: %w", err)
		}
	} else {
		// TODO: GetSpecByName() should return []byte
		b = []byte(sp.NewSpecLoader().GetSpecByName(specNameOrPath))
	}

	var complianceSpec ComplianceSpec
	if err = yaml.Unmarshal(b, &complianceSpec); err != nil {
		return ComplianceSpec{}, xerrors.Errorf("spec yaml decode error: %w", err)
	}
	return complianceSpec, nil

}
