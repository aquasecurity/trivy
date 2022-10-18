package spec

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"
)

// GetScannerTypes read spec control and detremine the scanners by check ID prefix
func GetScannerTypes(complianceSpec string) ([]types.SecurityCheck, error) {
	cs := ComplianceSpec{}
	err := yaml.Unmarshal([]byte(complianceSpec), &cs)
	if err != nil {
		return nil, err
	}
	scannerTypes := make([]types.SecurityCheck, 0)
	for _, control := range cs.Spec.Controls {
		for _, check := range control.Checks {
			scannerType := scannersByCheckIDPrefix(check.ID)
			if !slices.Contains(scannerTypes, scannerType) {
				scannerTypes = append(scannerTypes, scannerType)
			}
		}
	}
	return scannerTypes,nil
}

// ValidateScanners validate that scanner types are supported
func ValidateScanners(controls []Control) error {
	for _, control := range controls {
		for _, check := range control.Checks {
			scannerType := scannersByCheckIDPrefix(check.ID)
			if !slices.Contains(types.SecurityChecks, types.SecurityCheck(scannerType)) {
				return fmt.Errorf("scanner type %v is not supported", scannerType)
			}
		}
	}
	return nil
}

// ScannerCheckIDs return list of compliance check IDs
func ScannerCheckIDs(controls []Control) map[string][]string {
	scannerChecksMap := make(map[string][]string)
	for _, control := range controls {
		for _, check := range control.Checks {
			scannerType := scannersByCheckIDPrefix(check.ID)
			if _, ok := scannerChecksMap[scannerType]; !ok {
				scannerChecksMap[scannerType] = make([]string, 0)
			}
			if !slices.Contains(scannerChecksMap[scannerType], check.ID) {
				scannerChecksMap[scannerType] = append(scannerChecksMap[scannerType], check.ID)
			}
		}
	}
	return scannerChecksMap
}

func scannersByCheckIDPrefix(checkID string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(checkID), "cve-") || strings.HasPrefix(strings.ToLower(checkID), "dla-"):
		return "vuln"
	case strings.HasPrefix(strings.ToLower(checkID), "avd-"):
		return "config"
	default:
		return ""
	}
}
