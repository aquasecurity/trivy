package module

import (
	"context"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const mediaType = "application/vnd.module.wasm.content.layer.v1+wasm"

// Install installs a module
func Install(ctx context.Context, dir, repo string, quiet bool, opt types.RemoteOptions) error {
	ref, err := name.ParseReference(repo)
	if err != nil {
		return xerrors.Errorf("repository parse error: %w", err)
	}

	log.Logger.Infof("Installing the module from %s...", repo)
	artifact, err := oci.NewArtifact(repo, quiet, opt)
	if err != nil {
		return xerrors.Errorf("module initialize error: %w", err)
	}

	dst := filepath.Join(dir, ref.Context().Name())
	log.Logger.Debugf("Installing the module to %s...", dst)

	if err = artifact.Download(ctx, dst, oci.DownloadOption{MediaType: mediaType}); err != nil {
		return xerrors.Errorf("module download error: %w", err)
	}

	return nil
}

// Uninstall uninstalls a module
func Uninstall(_ context.Context, dir, repo string) error {
	ref, err := name.ParseReference(repo)
	if err != nil {
		return xerrors.Errorf("repository parse error: %w", err)
	}

	log.Logger.Infof("Uninstalling %s ...", repo)
	dst := filepath.Join(dir, ref.Context().Name())
	if err = os.RemoveAll(dst); err != nil {
		return xerrors.Errorf("remove error: %w", err)
	}

	return nil
}
