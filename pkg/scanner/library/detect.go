package library

import (
	"path/filepath"

	"github.com/aquasecurity/trivy/internal/rpc/client/library"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/knqyf263/go-version"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

type DetectorOperation interface {
	Detect(string, []ptypes.Library) ([]types.DetectedVulnerability, error)
}

func NewDetector(remoteURL, token string) DetectorOperation {
	if remoteURL != "" {
		return library.NewDetectClient(remoteURL, token)
	}
	return Detector{}
}

type Detector struct{}

func (d Detector) Detect(filePath string, pkgs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	log.Logger.Debugf("Detecting library vulnerabilities, path: %s", filePath)
	scanner := newScanner(filepath.Base(filePath))
	if scanner == nil {
		return nil, xerrors.New("unknown file type")
	}

	vulns, err := detect(scanner, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", scanner.Type(), err)
	}

	return vulns, nil
}

func detect(scanner ScannerOperation, libs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	log.Logger.Infof("Detecting %s vulnerabilities...", scanner.Type())
	var vulnerabilities []types.DetectedVulnerability
	for _, lib := range libs {
		v, err := version.NewVersion(lib.Version)
		if err != nil {
			log.Logger.Debug(err)
			continue
		}

		vulns, err := scanner.Detect(lib.Name, v)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", scanner.Type(), err)
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
