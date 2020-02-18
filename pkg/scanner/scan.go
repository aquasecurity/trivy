package scanner

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/wire"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker"
	ftypes "github.com/aquasecurity/fanal/types"
	libDetector "github.com/aquasecurity/trivy/pkg/detector/library"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/report"
	rpcLibDetector "github.com/aquasecurity/trivy/pkg/rpc/client/library"
	rpcOSDetector "github.com/aquasecurity/trivy/pkg/rpc/client/ospkg"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
	libScanner "github.com/aquasecurity/trivy/pkg/scanner/library"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	ospkgScanner "github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

var StandaloneSet = wire.NewSet(
	ospkgDetector.SuperSet,
	ospkgScanner.NewScanner,
	libDetector.SuperSet,
	libScanner.NewScanner,
	NewScanner,
)

var ClientSet = wire.NewSet(
	rpcOSDetector.SuperSet,
	ospkgScanner.NewScanner,
	rpcLibDetector.SuperSet,
	libScanner.NewScanner,
	NewScanner,
)

type Scanner struct {
	cacheClient  cache.Cache
	ospkgScanner ospkg.Scanner
	libScanner   library.Scanner
}

func NewScanner(cacheClient cache.Cache, ospkgScanner ospkg.Scanner, libScanner library.Scanner) Scanner {
	return Scanner{cacheClient: cacheClient, ospkgScanner: ospkgScanner, libScanner: libScanner}
}

func (s Scanner) ScanImage(imageName, filePath string, scanOptions types.ScanOptions, dockerOption ftypes.DockerOption) (report.Results, error) {
	results := report.Results{}
	ctx := context.Background()

	var target string
	var files extractor.FileMap
	var ac analyzer.Config

	ext, err := docker.NewDockerExtractor(dockerOption, s.cacheClient)
	if err != nil {
		return nil, err
	}
	ac = analyzer.Config{Extractor: ext}

	if imageName != "" {
		target = imageName
		files, err = ac.Analyze(ctx, imageName, dockerOption)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze image: %w", err)
		}
	} else if filePath != "" {
		target = filePath
		rc, err := openStream(filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open stream: %w", err)
		}

		files, err = ac.AnalyzeFile(ctx, rc)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, xerrors.New("image name or image file must be specified")
	}

	created, err := getCreated(files["/config"])
	if err != nil {
		return nil, err
	}

	if utils.StringInSlice("os", scanOptions.VulnType) {
		osFamily, osVersion, osVulns, err := s.ospkgScanner.Scan(target, created, files)
		if err != nil && err != ospkgDetector.ErrUnsupportedOS {
			return nil, xerrors.Errorf("failed to scan the image: %w", err)
		}
		if osFamily != "" {
			imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osVersion)
			results = append(results, report.Result{
				Target:          imageDetail,
				Vulnerabilities: osVulns,
			})
		}
	}

	if utils.StringInSlice("library", scanOptions.VulnType) {
		libVulns, err := s.libScanner.Scan(target, created, files)
		if err != nil {
			return nil, xerrors.Errorf("failed to scan libraries: %w", err)
		}

		var libResults report.Results
		for path, vulns := range libVulns {
			libResults = append(libResults, report.Result{
				Target:          path,
				Vulnerabilities: vulns,
			})
		}
		sort.Slice(libResults, func(i, j int) bool {
			return libResults[i].Target < libResults[j].Target
		})
		results = append(results, libResults...)
	}

	return results, nil
}

type config struct {
	Created time.Time
}

func getCreated(configBlob []byte) (time.Time, error) {
	var config config
	if err := json.Unmarshal(configBlob, &config); err != nil {
		return time.Time{}, xerrors.Errorf("invalid config JSON: %w", err)
	}
	return config.Created, nil
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
