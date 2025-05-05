//go:build wireinject
// +build wireinject

package artifact

import (
	"context"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scan"
)

//////////////
// Standalone
//////////////

// initializeImageScanService is for container image scanning in standalone mode
// e.g. dockerd, container registry, podman, etc.
func initializeImageScanService(ctx context.Context, imageName string, imageOpt types.ImageOptions, cacheOptions cache.Options, artifactOption artifact.Option) (
	scan.Service, func(), error,
) {
	wire.Build(scan.StandaloneDockerSet)
	return scan.Service{}, nil, nil
}

// initializeArchiveScanService is for container image archive scanning in standalone mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeArchiveScanService(ctx context.Context, filePath string, cacheOptions cache.Options, artifactOption artifact.Option) (
	scan.Service, func(), error,
) {
	wire.Build(scan.StandaloneArchiveSet)
	return scan.Service{}, nil, nil
}

// initializeFilesystemScanService is for filesystem scanning in standalone mode
func initializeFilesystemScanService(ctx context.Context, path string, cacheOptions cache.Options, artifactOption artifact.Option) (scan.Service, func(), error) {
	wire.Build(scan.StandaloneFilesystemSet)
	return scan.Service{}, nil, nil
}

// initializeRepositoryScanService is for repository scanning in standalone mode
func initializeRepositoryScanService(ctx context.Context, url string, cacheOptions cache.Options, artifactOption artifact.Option) (scan.Service, func(), error) {
	wire.Build(scan.StandaloneRepositorySet)
	return scan.Service{}, nil, nil
}

// initializeSBOMScanService is for sbom scanning in standalone mode
func initializeSBOMScanService(ctx context.Context, filePath string, cacheOptions cache.Options, artifactOption artifact.Option) (scan.Service, func(), error) {
	wire.Build(scan.StandaloneSBOMSet)
	return scan.Service{}, nil, nil
}

// initializeVMScanService is for vm scanning in standalone mode
func initializeVMScanService(ctx context.Context, filePath string, cacheOptions cache.Options, artifactOption artifact.Option) (
	scan.Service, func(), error,
) {
	wire.Build(scan.StandaloneVMSet)
	return scan.Service{}, nil, nil
}

/////////////////
// Client/Server
/////////////////

// initializeRemoteImageScanService is for container image scanning in client/server mode
// e.g. dockerd, container registry, podman, etc.
func initializeRemoteImageScanService(ctx context.Context, imageName string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, imageOpt types.ImageOptions, artifactOption artifact.Option) (
	scan.Service, func(), error,
) {
	wire.Build(scan.RemoteDockerSet)
	return scan.Service{}, nil, nil
}

// initializeRemoteArchiveScanService is for container image archive scanning in client/server mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeRemoteArchiveScanService(ctx context.Context, filePath string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option,
) (scan.Service, func(), error) {
	wire.Build(scan.RemoteArchiveSet)
	return scan.Service{}, nil, nil
}

// initializeRemoteFilesystemScanService is for filesystem scanning in client/server mode
func initializeRemoteFilesystemScanService(ctx context.Context, path string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option,
) (scan.Service, func(), error) {
	wire.Build(scan.RemoteFilesystemSet)
	return scan.Service{}, nil, nil
}

// initializeRemoteRepositoryScanService is for repository scanning in client/server mode
func initializeRemoteRepositoryScanService(ctx context.Context, url string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option) (
	scan.Service, func(), error,
) {
	wire.Build(scan.RemoteRepositorySet)
	return scan.Service{}, nil, nil
}

// initializeRemoteSBOMScanService is for sbom scanning in client/server mode
func initializeRemoteSBOMScanService(ctx context.Context, path string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option,
) (scan.Service, func(), error) {
	wire.Build(scan.RemoteSBOMSet)
	return scan.Service{}, nil, nil
}

// initializeRemoteVMScanService is for vm scanning in client/server mode
func initializeRemoteVMScanService(ctx context.Context, path string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option,
) (scan.Service, func(), error) {
	wire.Build(scan.RemoteVMSet)
	return scan.Service{}, nil, nil
}
