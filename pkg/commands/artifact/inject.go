//go:build wireinject
// +build wireinject

package artifact

import (
	"context"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

//////////////
// Standalone
//////////////

// initializeDockerScanner is for container image scanning in standalone mode
// e.g. dockerd, container registry, podman, etc.
func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, dockerOpt types.DockerOption, artifactOption artifact.Option) (
	scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneDockerSet)
	return scanner.Scanner{}, nil, nil
}

// initializeArchiveScanner is for container image archive scanning in standalone mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, error) {
	wire.Build(scanner.StandaloneArchiveSet)
	return scanner.Scanner{}, nil
}

// initializeFilesystemScanner is for filesystem scanning in standalone mode
func initializeFilesystemScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneFilesystemSet)
	return scanner.Scanner{}, nil, nil
}

func initializeRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneRepositorySet)
	return scanner.Scanner{}, nil, nil
}

func initializeSBOMScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneSBOMSet)
	return scanner.Scanner{}, nil, nil
}

func initializeVMScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (
	scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneVMSet)
	return scanner.Scanner{}, nil, nil
}

/////////////////
// Client/Server
/////////////////

// initializeRemoteDockerScanner is for container image scanning in client/server mode
// e.g. dockerd, container registry, podman, etc.
func initializeRemoteDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache,
	remoteScanOptions client.ScannerOption, dockerOpt types.DockerOption, artifactOption artifact.Option) (
	scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteDockerSet)
	return scanner.Scanner{}, nil, nil
}

// initializeRemoteArchiveScanner is for container image archive scanning in client/server mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeRemoteArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache,
	remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, error) {
	wire.Build(scanner.RemoteArchiveSet)
	return scanner.Scanner{}, nil
}

// initializeRemoteFilesystemScanner is for filesystem scanning in client/server mode
func initializeRemoteFilesystemScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache,
	remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteFilesystemSet)
	return scanner.Scanner{}, nil, nil
}

// initializeRemoteRepositoryScanner is for repository scanning in client/server mode
func initializeRemoteRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache,
	remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (
	scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteRepositorySet)
	return scanner.Scanner{}, nil, nil
}

// initializeRemoteSBOMScanner is for sbom scanning in client/server mode
func initializeRemoteSBOMScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache,
	remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteSBOMSet)
	return scanner.Scanner{}, nil, nil
}

// initializeRemoteVMScanner is for vm scanning in client/server mode
func initializeRemoteVMScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache,
	remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteVMSet)
	return scanner.Scanner{}, nil, nil
}
