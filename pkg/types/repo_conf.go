package types

import "os"

func InsecureSkipTLSForRepo() (insecureSkipTls bool) {
	insecureSkipTls = false
	if os.Getenv("TRIVY_INSECURE") != "" {
		insecureSkipTls = true
	}
	return insecureSkipTls
}
