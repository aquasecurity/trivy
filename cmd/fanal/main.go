package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact"
	aimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/artifact/remote"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() (err error) {
	ctx := context.Background()
	fsCache, err := cache.NewFSCache(utils.CacheDir())
	if err != nil {
		return err
	}

	app := &cli.App{
		Name:  "fanal",
		Usage: "A library to analyze a container image, local filesystem and remote repository",
		Commands: []*cli.Command{
			{
				Name:    "image",
				Aliases: []string{"img"},
				Usage:   "inspect a container image",
				Action:  globalOption(ctx, fsCache, imageAction),
			},
			{
				Name:    "archive",
				Aliases: []string{"ar"},
				Usage:   "inspect an image archive",
				Action:  globalOption(ctx, fsCache, archiveAction),
			},
			{
				Name:    "filesystem",
				Aliases: []string{"fs"},
				Usage:   "inspect a local directory",
				Action:  globalOption(ctx, fsCache, fsAction),
			},
			{
				Name:    "repository",
				Aliases: []string{"repo"},
				Usage:   "inspect a remote repository",
				Action:  globalOption(ctx, fsCache, repoAction),
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "clear", Aliases: []string{"s"}},
		},
	}

	return app.Run(os.Args)
}

func globalOption(ctx context.Context, fsCache cache.Cache, f func(context.Context, *cli.Context, cache.Cache) error) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		clearCache := c.Bool("clear")
		if clearCache {
			if err := fsCache.Clear(); err != nil {
				return xerrors.Errorf("%w", err)
			}
			return nil
		}
		return f(ctx, c, fsCache)
	}
}

func imageAction(ctx context.Context, c *cli.Context, fsCache cache.Cache) error {
	art, cleanup, err := imageArtifact(ctx, c.Args().First(), fsCache)
	if err != nil {
		return err
	}
	defer cleanup()
	return inspect(ctx, art, fsCache)
}

func archiveAction(ctx context.Context, c *cli.Context, fsCache cache.Cache) error {
	art, err := archiveImageArtifact(c.Args().First(), fsCache)
	if err != nil {
		return err
	}
	return inspect(ctx, art, fsCache)
}

func fsAction(ctx context.Context, c *cli.Context, fsCache cache.Cache) error {
	art := localArtifact(c.Args().First(), fsCache)
	return inspect(ctx, art, fsCache)
}

func repoAction(ctx context.Context, c *cli.Context, fsCache cache.Cache) error {
	art, cleanup, err := remoteArtifact(c.Args().First(), fsCache)
	if err != nil {
		return err
	}
	defer cleanup()
	return inspect(ctx, art, fsCache)
}

func inspect(ctx context.Context, artifact artifact.Artifact, c cache.LocalArtifactCache) error {
	imageInfo, err := artifact.Inspect(ctx)
	if err != nil {
		return err
	}

	a := applier.NewApplier(c)
	mergedLayer, err := a.ApplyLayers(imageInfo.ID, imageInfo.BlobIDs)
	if err != nil {
		switch err {
		case analyzer.ErrUnknownOS, analyzer.ErrNoPkgsDetected:
			fmt.Printf("WARN: %s\n", err)
		default:
			return err
		}
	}
	fmt.Println(imageInfo.Name)
	fmt.Printf("%+v\n", mergedLayer.OS)
	fmt.Printf("via image Packages: %d\n", len(mergedLayer.Packages))
	for _, app := range mergedLayer.Applications {
		fmt.Printf("%s (%s): %d\n", app.Type, app.FilePath, len(app.Libraries))
	}
	return nil
}

func imageArtifact(ctx context.Context, imageName string, c cache.ArtifactCache) (artifact.Artifact, func(), error) {
	opt := types.DockerOption{
		Timeout:  600 * time.Second,
		SkipPing: true,
	}

	img, cleanup, err := image.NewDockerImage(ctx, imageName, opt)
	if err != nil {
		return nil, func() {}, err
	}

	return aimage.NewArtifact(img, c), cleanup, nil
}

func archiveImageArtifact(imagePath string, c cache.ArtifactCache) (artifact.Artifact, error) {
	img, err := image.NewArchiveImage(imagePath)
	if err != nil {
		return nil, err
	}

	return aimage.NewArtifact(img, c), nil
}

func localArtifact(dir string, c cache.ArtifactCache) artifact.Artifact {
	return local.NewArtifact(dir, c)
}

func remoteArtifact(dir string, c cache.ArtifactCache) (artifact.Artifact, func(), error) {
	return remote.NewArtifact(dir, c)
}
