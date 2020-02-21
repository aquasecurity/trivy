package scanner

import (
	"context"

	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

// StandaloneSuperSet is used in the standalone mode
var StandaloneSuperSet = wire.NewSet(
	analyzer.New,
	wire.Bind(new(Analyzer), new(analyzer.Config)),
	local.SuperSet,
	wire.Bind(new(Driver), new(local.Scanner)),
	NewScanner,
)

var StandaloneDockerSet = wire.NewSet(
	types.GetDockerOption,
	docker.NewDockerExtractor,
	wire.Bind(new(extractor.Extractor), new(docker.Extractor)),
	StandaloneSuperSet,
)

var StandaloneArchiveSet = wire.NewSet(
	types.GetDockerOption,
	docker.NewDockerArchiveExtractor,
	wire.Bind(new(extractor.Extractor), new(docker.Extractor)),
	StandaloneSuperSet,
)

// RemoteSuperSet is used in the client mode
var RemoteSuperSet = wire.NewSet(
	analyzer.New,
	wire.Bind(new(Analyzer), new(analyzer.Config)),
	client.SuperSet,
	wire.Bind(new(Driver), new(client.Scanner)),
	NewScanner,
)

var RemoteDockerSet = wire.NewSet(
	types.GetDockerOption,
	docker.NewDockerExtractor,
	wire.Bind(new(extractor.Extractor), new(docker.Extractor)),
	RemoteSuperSet,
)

var RemoteArchiveSet = wire.NewSet(
	types.GetDockerOption,
	docker.NewDockerArchiveExtractor,
	wire.Bind(new(extractor.Extractor), new(docker.Extractor)),
	RemoteSuperSet,
)

type Scanner struct {
	driver   Driver
	analyzer Analyzer
}

type Driver interface {
	Scan(target string, imageID digest.Digest, layerIDs []string, options types.ScanOptions) (results report.Results, osFound *ftypes.OS, eols bool, err error)
}

type Analyzer interface {
	Analyze(ctx context.Context) (info ftypes.ImageReference, err error)
}

func NewScanner(driver Driver, ac Analyzer) Scanner {
	return Scanner{driver: driver, analyzer: ac}
}

func (s Scanner) ScanImage(options types.ScanOptions) (report.Results, error) {
	ctx := context.Background()
	imageInfo, err := s.analyzer.Analyze(ctx)
	if err != nil {
		return nil, xerrors.Errorf("failed analysis: %w", err)
	}

	log.Logger.Debugf("Image ID: %s", imageInfo.ID)
	log.Logger.Debugf("Layer IDs: %v", imageInfo.LayerIDs)

	results, osFound, eosl, err := s.driver.Scan(imageInfo.Name, imageInfo.ID, imageInfo.LayerIDs, options)
	if err != nil {
		return nil, xerrors.Errorf("scan failed: %w", err)
	}
	if eosl {
		log.Logger.Warnf("This OS version is no longer supported by the distribution: %s %s", osFound.Family, osFound.Name)
		log.Logger.Warnf("The vulnerability detection may be insufficient because security updates are not provided")
	}

	return results, nil
}
