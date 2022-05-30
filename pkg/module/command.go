package module

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const mediaType = "application/vnd.module.wasm.content.layer.v1+wasm"

// Install installs a module
func Install(ctx context.Context, repo string, quiet, insecure bool) error {
	log.Logger.Infof("Installing the module from %s...", repo)
	artifact, err := oci.NewArtifact(repo, mediaType, quiet, insecure)
	if err != nil {
		return err
	}

	if err = artifact.Download(ctx, dir()); err != nil {
		return err
	}

	return nil
}
