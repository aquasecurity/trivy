package licensing

import (
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/fanal/licensing/classification"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"golang.org/x/xerrors"
)

type Scanner struct {
	classifier *classification.Classifier
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func NewScanner(ignoredLicenses []string) (Scanner, error) {

	classifier, err := NewClassifier()
	if err != nil {
		return Scanner{}, xerrors.Errorf("classifier could not be created: %w", err)
	}
	return Scanner{classifier: classifier}, nil
}

func (s Scanner) Scan(scanArgs ScanArgs) types.LicenseFile {
	return types.LicenseFile{}
}
