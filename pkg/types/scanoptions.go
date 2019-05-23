package types

type ScanOptions struct {
	VulnType []string
}

func IsVulnTypeSelected(scanOptions ScanOptions, vulnType string) bool {
	vulnList := scanOptions.VulnType
	for i := 0; i < len(vulnList); i++ {
		if vulnType == vulnList[i] {
			return true
		}
	}
	return false
}
