package scanner

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/genuinetools/reg/registry"

	"github.com/knqyf263/trivy/pkg/log"

	"github.com/knqyf263/trivy/pkg/scanner/library"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/scanner/ospkg"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func ScanImage(imageName, filePath string) (map[string][]vulnerability.DetectedVulnerability, error) {
	var err error
	results := map[string][]vulnerability.DetectedVulnerability{}
	ctx := context.Background()

	image, err := registry.ParseImage(imageName)
	if err != nil {
		return nil, xerrors.Errorf("invalid image: %w", err)
	}
	if image.Tag == "latest" {
		log.Logger.Warn("You should avoid using the :latest tag as it is cached. You need to specify '--clean' option when :latest image is changed")
	}

	var target string
	var files extractor.FileMap
	if imageName != "" {
		target = imageName
		files, err = analyzer.Analyze(ctx, imageName)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze image: %w", err)
		}
	} else if filePath != "" {
		target = filePath
		rc, err := openStream(filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open stream: %w", err)
		}

		files, err = analyzer.AnalyzeFromFile(ctx, rc)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, xerrors.New("image name or image file must be specified")
	}

	osFamily, osVersion, osVulns, err := ospkg.Scan(files)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan image: %w", err)

	}
	imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osVersion)
	results[imageDetail] = osVulns

	libVulns, err := library.Scan(files)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan libraries: %w", err)
	}
	for path, vulns := range libVulns {
		results[path] = vulns
	}

	return results, nil
}

func ScanFile(f *os.File) (map[string][]vulnerability.DetectedVulnerability, error) {
	vulns, err := library.ScanFile(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan libraries in file: %w", err)
	}
	results := map[string][]vulnerability.DetectedVulnerability{
		f.Name(): vulns,
	}
	return results, nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}
