package licensing

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Scanner struct {
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func NewScanner(ignoredLicenses []string) (Scanner, error) {
	return Scanner{}, nil
}

func (s Scanner) Scan() types.LicenseFile {
	// TODO: license type detection
	// https://github.com/google/licenseclassifier/blob/7c62d6fe8d3aa2f39c4affb58c9781d9dc951a2d/license_type.go#L377-L394
	return types.LicenseFile{}
}
