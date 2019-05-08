# fanal
Static Analysis Library for Containers

[![GoDoc](https://godoc.org/github.com/knqyf263/fanal?status.svg)](https://godoc.org/github.com/knqyf263/fanal)
[![Build Status](https://travis-ci.org/knqyf263/fanal.svg?branch=master)](https://travis-ci.org/knqyf263/fanal)
[![Coverage Status](https://coveralls.io/repos/github/knqyf263/fanal/badge.svg?branch=master)](https://coveralls.io/github/knqyf263/fanal?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/fanal)](https://goreportcard.com/report/github.com/knqyf263/fanal)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/knqyf263/fanal/blob/master/LICENSE)

## Feature
- Detect OS
- Extract OS packages
- Extract libraries used by an application
  - Bundler, Composer, npm, Pipenv

## Example
See `cmd/fanal/`

```
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/cache"

	"github.com/knqyf263/fanal/analyzer"
	_ "github.com/knqyf263/fanal/analyzer/library/bundler"
	_ "github.com/knqyf263/fanal/analyzer/library/composer"
	_ "github.com/knqyf263/fanal/analyzer/library/npm"
	_ "github.com/knqyf263/fanal/analyzer/library/pipenv"
	_ "github.com/knqyf263/fanal/analyzer/os/alpine"
	_ "github.com/knqyf263/fanal/analyzer/os/amazonlinux"
	_ "github.com/knqyf263/fanal/analyzer/os/debianbase"
	_ "github.com/knqyf263/fanal/analyzer/os/opensuse"
	_ "github.com/knqyf263/fanal/analyzer/os/redhatbase"
	_ "github.com/knqyf263/fanal/analyzer/pkg/apk"
	_ "github.com/knqyf263/fanal/analyzer/pkg/dpkg"
	_ "github.com/knqyf263/fanal/analyzer/pkg/rpm"
	"github.com/knqyf263/fanal/extractor"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	ctx := context.Background()
	tarPath := flag.String("f", "-", "layer.tar path")
	clearCache := flag.Bool("clear", false, "clear cache")
	flag.Parse()

	if *clearCache {
		if err = cache.Clear(); err != nil {
			return xerrors.Errorf("error in cache clear: %w", err)
		}
	}

	args := flag.Args()

	var files extractor.FileMap
	if len(args) > 0 {
		files, err = analyzer.Analyze(ctx, args[0])
		if err != nil {
			return err
		}
	} else {
		rc, err := openStream(*tarPath)
		if err != nil {
			return err
		}

		files, err = analyzer.AnalyzeFromFile(ctx, rc)
		if err != nil {
			return err
		}
	}

	os, err := analyzer.GetOS(files)
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", os)

	pkgs, err := analyzer.GetPackages(files)
	if err != nil {
		return err
	}
	fmt.Printf("Packages: %d\n", len(pkgs))

	libs, err := analyzer.GetLibraries(files)
	if err != nil {
		return err
	}
	for filepath, libList := range libs {
		fmt.Printf("%s: %d\n", filepath, len(libList))
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

```


## Notes
When using `latest` tag, that image will be cached. After `latest` tag is updated, you need to clear cache.



