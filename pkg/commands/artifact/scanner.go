package artifact

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scanner"
)

// imageStandaloneScanner initializes a container image scanner in standalone mode
// $ trivy image alpine:3.15
func imageStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeImageScanner(ctx, conf.Target, conf.ArtifactOption.ImageOption, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize an image scanner: %w", err)
	}
	return s, cleanup, nil
}

// archiveStandaloneScanner initializes an image archive scanner in standalone mode
// $ trivy image --input alpine.tar
func archiveStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeArchiveScanner(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, cleanup, nil
}

// imageRemoteScanner initializes a container image scanner in client/server mode
// $ trivy image --server localhost:4954 alpine:3.15
func imageRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeRemoteImageScanner(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption,
		conf.ArtifactOption.ImageOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, nil, xerrors.Errorf("unable to initialize a remote image scanner: %w", err)
	}
	return s, cleanup, nil
}

// archiveRemoteScanner initializes an image archive scanner in client/server mode
// $ trivy image --server localhost:4954 --input alpine.tar
func archiveRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	// Scan tar file
	s, cleanup, err := initializeRemoteArchiveScanner(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, nil, xerrors.Errorf("unable to initialize the remote archive scanner: %w", err)
	}
	return s, cleanup, nil
}

// filesystemStandaloneScanner initializes a filesystem scanner in standalone mode
func filesystemStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeFilesystemScanner(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// filesystemRemoteScanner initializes a filesystem scanner in client/server mode
func filesystemRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeRemoteFilesystemScanner(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// repositoryStandaloneScanner initializes a repository scanner in standalone mode
func repositoryStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeRepositoryScanner(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a repository scanner: %w", err)
	}
	return s, cleanup, nil
}

// repositoryRemoteScanner initializes a repository scanner in client/server mode
func repositoryRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeRemoteRepositoryScanner(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption,
		conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote repository scanner: %w", err)
	}
	return s, cleanup, nil
}

// sbomStandaloneScanner initializes a SBOM scanner in standalone mode
func sbomStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeSBOMScanner(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a cycloneDX scanner: %w", err)
	}
	return s, cleanup, nil
}

// sbomRemoteScanner initializes a SBOM scanner in client/server mode
func sbomRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeRemoteSBOMScanner(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote cycloneDX scanner: %w", err)
	}
	return s, cleanup, nil
}

// vmStandaloneScanner initializes a VM scanner in standalone mode
func vmStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeVMScanner(ctx, conf.Target, conf.CacheOptions, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a vm scanner: %w", err)
	}
	return s, cleanup, nil
}

// vmRemoteScanner initializes a VM scanner in client/server mode
func vmRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Service, func(), error) {
	s, cleanup, err := initializeRemoteVMScanner(ctx, conf.Target, conf.RemoteCacheOptions, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Service{}, func() {}, xerrors.Errorf("unable to initialize a remote vm scanner: %w", err)
	}
	return s, cleanup, nil
}
