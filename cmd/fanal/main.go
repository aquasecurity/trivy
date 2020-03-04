package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/utils"
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
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() (err error) {
	ctx := context.Background()
	tarPath := flag.String("f", "-", "layer.tar path")
	clearCache := flag.Bool("clear", false, "clear cache")
	flag.Parse()

	c, err := cache.NewFSCache(utils.CacheDir())
	if err != nil {
		return err
	}

	if *clearCache {
		if err = c.Clear(); err != nil {
			return xerrors.Errorf("%w", err)
		}
		return nil
	}

	args := flag.Args()

	opt := types.DockerOption{
		Timeout:  600 * time.Second,
		SkipPing: true,
	}

	var ext extractor.Extractor
	var cleanup func()
	if len(args) > 0 {
		ext, cleanup, err = docker.NewDockerExtractor(ctx, args[0], opt)
		if err != nil {
			return err
		}
	} else {
		ext, cleanup, err = docker.NewDockerArchiveExtractor(ctx, *tarPath, opt)
		if err != nil {
			return err
		}
	}
	defer cleanup()

	ac := analyzer.New(ext, c)
	imageInfo, err := ac.Analyze(ctx)
	if err != nil {
		return err
	}

	a := analyzer.NewApplier(c)
	mergedLayer, err := a.ApplyLayers(imageInfo.ID, imageInfo.LayerIDs)
	if err != nil {
		return err
	}

	fmt.Printf("%+v\n", mergedLayer.OS)
	fmt.Printf("via image Packages: %d\n", len(mergedLayer.Packages))
	for _, app := range mergedLayer.Applications {
		fmt.Printf("%s (%s): %d\n", app.Type, app.FilePath, len(app.Libraries))
	}
	return nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}
