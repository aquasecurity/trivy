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

	classifier, err := classification.NewClassifier(ignoredLicenses)
	if err != nil {
		return Scanner{}, xerrors.Errorf("classifier could not be created: %w", err)
	}
	return Scanner{classifier: classifier}, nil
}

func (s Scanner) ScanFS(filesystem fs.FS) ([]types.LicenseFile, error) {

	var licenseFiles []types.LicenseFile

	err := fs.WalkDir(filesystem, ".", func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		content, err := fs.ReadFile(filesystem, path)
		if err != nil {
			return err
		}
		licenseFile, err := s.classifier.Classify(path, content)
		if err != nil {
			return err
		}

		if len(licenseFile.Findings) > 0 {
			licenseFiles = append(licenseFiles, licenseFile)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return licenseFiles, nil
}

func (s Scanner) Scan(scanArgs ScanArgs) types.LicenseFile {

	license, err := s.classifier.Classify(scanArgs.FilePath, scanArgs.Content)
	if err != nil {
		log.Logger.Debugf("Name scan failed while scanning %s: %w", scanArgs.FilePath, err)
	}

	return license
}
