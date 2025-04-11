package artifact

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scan"
)

// imageStandaloneScanService initializes a container image scan service in standalone mode
// $ trivy image alpine:3.15
func imageStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeImageScanService(ctx, conf.Target, conf.ArtifactOption.ImageOption, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize an image scan service: %w", err)
	}
	return s, cleanup, nil
}

// archiveStandaloneScanService initializes an image archive scan srevice in standalone mode
// $ trivy image --input alpine.tar
func archiveStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeArchiveScanService(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize the archive scan service: %w", err)
	}
	return s, cleanup, nil
}

// imageRemoteScanService initializes a container image scan service in client/server mode
// $ trivy image --server localhost:4954 alpine:3.15
func imageRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeRemoteImageScanService(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption,
		conf.ArtifactOption.ImageOption, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, nil, xerrors.Errorf("unable to initialize a remote image scan service: %w", err)
	}
	return s, cleanup, nil
}

// archiveRemoteScanService initializes an image archive scan service in client/server mode
// $ trivy image --server localhost:4954 --input alpine.tar
func archiveRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Scan tar file
	s, cleanup, err := initializeRemoteArchiveScanService(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, nil, xerrors.Errorf("unable to initialize the remote archive scan service: %w", err)
	}
	return s, cleanup, nil
}

// filesystemStandaloneScanService initializes a filesystem scan service in standalone mode
func filesystemStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeFilesystemScanService(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scan service: %w", err)
	}
	return s, cleanup, nil
}

// filesystemRemoteScanService initializes a filesystem scan service in client/server mode
func filesystemRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeRemoteFilesystemScanService(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote filesystem scan service: %w", err)
	}
	return s, cleanup, nil
}

// repositoryStandaloneScanService initializes a repository scan service in standalone mode
func repositoryStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeRepositoryScanService(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a repository scan service: %w", err)
	}
	return s, cleanup, nil
}

// repositoryRemoteScanService initializes a repository scan service in client/server mode
func repositoryRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeRemoteRepositoryScanService(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption,
		conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote repository scan service: %w", err)
	}
	return s, cleanup, nil
}

// sbomStandaloneScanService initializes a SBOM scan service in standalone mode
func sbomStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeSBOMScanService(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a cycloneDX scan service: %w", err)
	}
	return s, cleanup, nil
}

// sbomRemoteScanService initializes a SBOM scan service in client/server mode
func sbomRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeRemoteSBOMScanService(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote cycloneDX scan service: %w", err)
	}
	return s, cleanup, nil
}

// vmStandaloneScanService initializes a VM scan service in standalone mode
func vmStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeVMScanService(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a vm scan service: %w", err)
	}
	return s, cleanup, nil
}

// vmRemoteScanService initializes a VM scan service in client/server mode
func vmRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	s, cleanup, err := initializeRemoteVMScanService(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scan.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote vm scan service: %w", err)
	}
	return s, cleanup, nil
}
