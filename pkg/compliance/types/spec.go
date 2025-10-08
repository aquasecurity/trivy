package types

import (
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/set"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Spec represent the compliance specification
type Spec struct {
	Spec iacTypes.Spec `yaml:"spec"`
}

// Scanners reads spec control and determines the scanners by check ID prefix
func (cs *Spec) Scanners() (types.Scanners, error) {
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
func (cs *Spec) CheckIDs() map[types.Scanner][]string {
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
