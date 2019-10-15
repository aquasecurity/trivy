package scanner

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

func ScanImage(imageName, filePath string, scanOptions types.ScanOptions) (report.Results, error) {
	results := report.Results{}
	ctx := context.Background()

	var target string
	var files extractor.FileMap
	if imageName != "" {
		target = imageName
		dockerOption, err := types.GetDockerOption()
		if err != nil {
			return nil, xerrors.Errorf("failed to get docker option: %w", err)
		}

		dockerOption.Timeout = scanOptions.Timeout
		files, err = analyzer.Analyze(ctx, imageName, dockerOption)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze image: %w", err)
		}
	} else if filePath != "" {
		target = filePath
		rc, err := openStream(filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open stream: %w", err)
		}

		files, err = analyzer.AnalyzeFile(ctx, rc)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, xerrors.New("image name or image file must be specified")
	}

	if utils.StringInSlice("os", scanOptions.VulnType) {
		osFamily, osVersion, osVulns, err := ospkg.Scan(files)
		if err != nil {
			return nil, xerrors.Errorf("failed to scan image: %w", err)
		}
		if osFamily != "" {
			imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osVersion)
			results = append(results, report.Result{
				FileName:        imageDetail,
				Vulnerabilities: osVulns,
			})
		}
	}

	if utils.StringInSlice("library", scanOptions.VulnType) {
		libVulns, err := library.Scan(files, scanOptions)
		if err != nil {
			return nil, xerrors.Errorf("failed to scan libraries: %w", err)
		}

		var libResults report.Results
		for path, vulns := range libVulns {
			libResults = append(libResults, report.Result{
				FileName:        path,
				Vulnerabilities: vulns,
			})
		}
		sort.Slice(libResults, func(i, j int) bool {
			return libResults[i].FileName < libResults[j].FileName
		})
		results = append(results, libResults...)
	}

	return results, nil
}

func ScanFile(f *os.File) (report.Results, error) {
	vulns, err := library.ScanFile(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan libraries in file: %w", err)
	}
	results := report.Results{
		{FileName: f.Name(), Vulnerabilities: vulns},
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
