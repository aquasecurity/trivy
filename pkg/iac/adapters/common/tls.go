package common

import "strings"

// Flexible servers report the minimum TLS version in the Azure parameter format,
// e.g. TLSv1.2, while single servers and the checks use the TLS1_2 format.
var azureTLSVersions = map[string]string{
	"tlsv1":   "TLS1_0",
	"tlsv1.0": "TLS1_0",
	"tlsv1.1": "TLS1_1",
	"tlsv1.2": "TLS1_2",
	"tlsv1.3": "TLS1_3",
}

// MinimumAzureTLSVersion converts an Azure TLS version to the TLS1_2 format.
// MySQL flexible servers accept a comma-separated list of allowed versions,
// in which case the lowest one is returned. Unrecognized versions are skipped,
// and the value is left as is if none of them is recognized.
func MinimumAzureTLSVersion(val string) string {
	var minimum string
	for version := range strings.SplitSeq(val, ",") {
		normalized, ok := azureTLSVersions[strings.ToLower(strings.TrimSpace(version))]
		if !ok {
			continue
		}
		if minimum == "" || normalized < minimum {
			minimum = normalized
		}
	}

	if minimum == "" {
		return val
	}

	return minimum
}
