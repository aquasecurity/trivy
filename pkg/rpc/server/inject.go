// +build wireinject

package server

import (
	"github.com/aquasecurity/fanal/cache"
	"github.com/google/wire"
)

func initializeScanServer(localArtifactCache cache.LocalArtifactCache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}

func initializeDBWorker(cacheDir string, quiet bool) dbWorker {
	wire.Build(DBWorkerSuperSet)
	return dbWorker{}
}
