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
	"github.com/aquasecurity/trivy/pkg/scanner"
)

//////////////
// Standalone
//////////////

// initializeImageScanner is for container image scanning in standalone mode
// e.g. dockerd, container registry, podman, etc.
func initializeImageScanner(ctx context.Context, imageName string, imageOpt types.ImageOptions, cacheOptions cache.Options, artifactOption artifact.Option) (
	scanner.Service, func(), error) {
	wire.Build(scanner.StandaloneDockerSet)
	return scanner.Service{}, nil, nil
}

// initializeArchiveScanner is for container image archive scanning in standalone mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeArchiveScanner(ctx context.Context, filePath string, cacheOptions cache.Options, artifactOption artifact.Option) (
	scanner.Service, func(), error) {
	wire.Build(scanner.StandaloneArchiveSet)
	return scanner.Service{}, nil, nil
}

// initializeFilesystemScanner is for filesystem scanning in standalone mode
func initializeFilesystemScanner(ctx context.Context, path string, cacheOptions cache.Options, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.StandaloneFilesystemSet)
	return scanner.Service{}, nil, nil
}

func initializeRepositoryScanner(ctx context.Context, url string, cacheOptions cache.Options, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.StandaloneRepositorySet)
	return scanner.Service{}, nil, nil
}

func initializeSBOMScanner(ctx context.Context, filePath string, cacheOptions cache.Options, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.StandaloneSBOMSet)
	return scanner.Service{}, nil, nil
}

func initializeVMScanner(ctx context.Context, filePath string, cacheOptions cache.Options, artifactOption artifact.Option) (
	scanner.Service, func(), error) {
	wire.Build(scanner.StandaloneVMSet)
	return scanner.Service{}, nil, nil
}

/////////////////
// Client/Server
/////////////////

// initializeRemoteImageScanner is for container image scanning in client/server mode
// e.g. dockerd, container registry, podman, etc.
func initializeRemoteImageScanner(ctx context.Context, imageName string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, imageOpt types.ImageOptions, artifactOption artifact.Option) (
	scanner.Service, func(), error) {
	wire.Build(scanner.RemoteDockerSet)
	return scanner.Service{}, nil, nil
}

// initializeRemoteArchiveScanner is for container image archive scanning in client/server mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeRemoteArchiveScanner(ctx context.Context, filePath string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.RemoteArchiveSet)
	return scanner.Service{}, nil, nil
}

// initializeRemoteFilesystemScanner is for filesystem scanning in client/server mode
func initializeRemoteFilesystemScanner(ctx context.Context, path string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.RemoteFilesystemSet)
	return scanner.Service{}, nil, nil
}

// initializeRemoteRepositoryScanner is for repository scanning in client/server mode
func initializeRemoteRepositoryScanner(ctx context.Context, url string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option) (
	scanner.Service, func(), error) {
	wire.Build(scanner.RemoteRepositorySet)
	return scanner.Service{}, nil, nil
}

// initializeRemoteSBOMScanner is for sbom scanning in client/server mode
func initializeRemoteSBOMScanner(ctx context.Context, path string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.RemoteSBOMSet)
	return scanner.Service{}, nil, nil
}

// initializeRemoteVMScanner is for vm scanning in client/server mode
func initializeRemoteVMScanner(ctx context.Context, path string, remoteCacheOptions cache.RemoteOptions,
	remoteScanOptions client.ServiceOption, artifactOption artifact.Option) (scanner.Service, func(), error) {
	wire.Build(scanner.RemoteVMSet)
	return scanner.Service{}, nil, nil
}
