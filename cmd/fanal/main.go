package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact"
	aimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/artifact/remote"
	"github.com/aquasecurity/fanal/cache"
	_ "github.com/aquasecurity/fanal/hook/all"
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
	app := &cli.App{
		Name:  "fanal",
		Usage: "A library to analyze a container image, local filesystem and remote repository",
		Commands: []*cli.Command{
			{
				Name:    "image",
				Aliases: []string{"img"},
				Usage:   "inspect a container image",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "conf-policy",
						Usage: "policy paths",
					},
					&cli.StringSliceFlag{
						Name:  "skip-files",
						Usage: "skip files",
					},
					&cli.StringSliceFlag{
						Name:  "skip-dirs",
						Usage: "skip dirs",
					},
				},
				Action: globalOption(imageAction),
			},
			{
				Name:    "archive",
				Aliases: []string{"ar"},
				Usage:   "inspect an image archive",
				Action:  globalOption(archiveAction),
			},
			{
				Name:    "filesystem",
				Aliases: []string{"fs"},
				Usage:   "inspect a local directory",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "namespace",
						Usage: "namespaces",
						Value: cli.NewStringSlice("appshield"),
					},
					&cli.StringSliceFlag{
						Name:  "policy",
						Usage: "policy paths",
					},
					&cli.StringSliceFlag{
						Name:  "skip-files",
						Usage: "skip files",
					},
					&cli.StringSliceFlag{
						Name:  "skip-dirs",
						Usage: "skip dirs",
					},
				},
				Action: globalOption(fsAction),
			},
			{
				Name:    "repository",
				Aliases: []string{"repo"},
				Usage:   "inspect a remote repository",
				Action:  globalOption(repoAction),
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "clear", Aliases: []string{"s"}},
			&cli.StringFlag{
				Name:    "cache",
				Aliases: []string{"c"},
				Usage:   "cache backend (e.g. redis://localhost:6379)",
			},
		},
	}

	return app.Run(os.Args)
}

func globalOption(f func(*cli.Context, cache.Cache) error) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		cacheClient, err := initializeCache(c.String("cache"))
		if err != nil {
			return err
		}
		defer cacheClient.Close()

		clearCache := c.Bool("clear")
		if clearCache {
			if err := cacheClient.Clear(); err != nil {
				return xerrors.Errorf("%w", err)
			}
			return nil
		}
		return f(c, cacheClient)
	}
}

func initializeCache(backend string) (cache.Cache, error) {
	var cacheClient cache.Cache
	var err error

	if strings.HasPrefix(backend, "redis://") {
		cacheClient = cache.NewRedisCache(&redis.Options{
			Addr: strings.TrimPrefix(backend, "redis://"),
		})
	} else {
		cacheClient, err = cache.NewFSCache(utils.CacheDir())
	}
	return cacheClient, err
}

func imageAction(c *cli.Context, fsCache cache.Cache) error {
	artifactOpt := artifact.Option{
		SkipFiles: c.StringSlice("skip-files"),
		SkipDirs:  c.StringSlice("skip-dirs"),

		MisconfScannerOption: config.ScannerOption{
			PolicyPaths: c.StringSlice("policy"),
		},
	}

	art, cleanup, err := imageArtifact(c.Context, c.Args().First(), fsCache, artifactOpt)
	if err != nil {
		return err
	}
	defer cleanup()
	return inspect(c.Context, art, fsCache)
}

func archiveAction(c *cli.Context, fsCache cache.Cache) error {
	art, err := archiveImageArtifact(c.Args().First(), fsCache)
	if err != nil {
		return err
	}
	return inspect(c.Context, art, fsCache)
}

func fsAction(c *cli.Context, fsCache cache.Cache) error {
	artifactOpt := artifact.Option{
		SkipFiles: c.StringSlice("skip-files"),
		SkipDirs:  c.StringSlice("skip-dirs"),

		MisconfScannerOption: config.ScannerOption{
			Namespaces:  []string{"appshield"},
			PolicyPaths: c.StringSlice("policy"),
		},
	}

	art, err := local.NewArtifact(c.Args().First(), fsCache, artifactOpt)
	if err != nil {
		return err
	}

	return inspect(c.Context, art, fsCache)
}

func repoAction(c *cli.Context, fsCache cache.Cache) error {
	art, cleanup, err := remoteArtifact(c.Args().First(), fsCache)
	if err != nil {
		return err
	}
	defer cleanup()
	return inspect(c.Context, art, fsCache)
}

func inspect(ctx context.Context, art artifact.Artifact, c cache.LocalArtifactCache) error {
	imageInfo, err := art.Inspect(ctx)
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
	fmt.Printf("RepoTags: %v\n", imageInfo.ImageMetadata.RepoTags)
	fmt.Printf("RepoDigests: %v\n", imageInfo.ImageMetadata.RepoDigests)
	fmt.Printf("%+v\n", mergedLayer.OS)
	fmt.Printf("via image Packages: %d\n", len(mergedLayer.Packages))
	for _, app := range mergedLayer.Applications {
		fmt.Printf("%s (%s): %d\n", app.Type, app.FilePath, len(app.Libraries))
	}

	if len(mergedLayer.Misconfigurations) > 0 {
		fmt.Println("Misconfigurations:")
	}
	for _, misconf := range mergedLayer.Misconfigurations {
		fmt.Printf("  %s: failures %d, warnings %d\n", misconf.FilePath, len(misconf.Failures), len(misconf.Warnings))
		for _, failure := range misconf.Failures {
			fmt.Printf("    %s: %s\n", failure.ID, failure.Message)
		}
	}
	return nil
}

func imageArtifact(ctx context.Context, imageName string, c cache.ArtifactCache,
	artifactOpt artifact.Option) (artifact.Artifact, func(), error) {
	img, cleanup, err := image.NewDockerImage(ctx, imageName, types.DockerOption{})
	if err != nil {
		return nil, func() {}, err
	}

	art, err := aimage.NewArtifact(img, c, artifactOpt)
	if err != nil {
		return nil, func() {}, err
	}
	return art, cleanup, nil
}

func archiveImageArtifact(imagePath string, c cache.ArtifactCache) (artifact.Artifact, error) {
	img, err := image.NewArchiveImage(imagePath)
	if err != nil {
		return nil, err
	}

	art, err := aimage.NewArtifact(img, c, artifact.Option{})
	if err != nil {
		return nil, err
	}
	return art, nil
}

func remoteArtifact(dir string, c cache.ArtifactCache) (artifact.Artifact, func(), error) {
	return remote.NewArtifact(dir, c, artifact.Option{})
}
