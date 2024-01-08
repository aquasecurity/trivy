//go:build wireinject
// +build wireinject

package k8s

import (
	"github.com/google/wire"

	"github.com/deepfactor-io/trivy/pkg/fanal/cache"
)

func initializeScanK8s(localArtifactCache cache.LocalArtifactCache) *ScanKubernetes {
	wire.Build(ScanSuperSet)
	return &ScanKubernetes{}
}
