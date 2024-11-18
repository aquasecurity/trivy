package module

import (
	"context"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/asset"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const mediaType = "application/vnd.module.wasm.content.layer.v1+wasm"

// Install installs a module
func Install(ctx context.Context, dir, repo string, quiet bool, opts types.RegistryOptions) error {
	ref, err := name.ParseReference(repo)
	if err != nil {
		return xerrors.Errorf("repository parse error: %w", err)
	}

	log.Info("Installing the module from the repository...", log.String("repo", repo))
	art := asset.NewOCI(repo, asset.Options{
		MediaType:       mediaType,
		Quiet:           quiet,
		RegistryOptions: opts,
	})

	dst := filepath.Join(dir, ref.Context().Name())
	log.Debug("Installing the module...", log.String("dst", dst))
	if err = art.Download(ctx, dst); err != nil {
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

	log.Info("Uninstalling the module ...", log.String("module", repo))
	dst := filepath.Join(dir, ref.Context().Name())
	if err = os.RemoveAll(dst); err != nil {
		return xerrors.Errorf("remove error: %w", err)
	}

	return nil
}
