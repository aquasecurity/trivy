package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/knqyf263/fanal/analyzer"
	_ "github.com/knqyf263/fanal/analyzer/os/alpine"
	_ "github.com/knqyf263/fanal/analyzer/os/amazonlinux"
	_ "github.com/knqyf263/fanal/analyzer/os/debian"
	_ "github.com/knqyf263/fanal/analyzer/os/opensuse"
	_ "github.com/knqyf263/fanal/analyzer/os/redhatbase"
	_ "github.com/knqyf263/fanal/analyzer/os/ubuntu"
	_ "github.com/knqyf263/fanal/analyzer/pkg/apk"
	_ "github.com/knqyf263/fanal/analyzer/pkg/dpkg"
	_ "github.com/knqyf263/fanal/analyzer/pkg/rpm"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	ctx := context.Background()
	imageName := os.Args[1]

	files, err := analyzer.Analyze(ctx, imageName)
	if err != nil {
		log.Fatal(err)
	}
	analyzer.GetOS(files)
	analyzer.GetPackages(files)
}

func main2() {
	ctx := context.Background()
	tarPath := flag.String("f", "-", "layer.tar path")
	flag.Parse()
	rc, err := openStream(*tarPath)
	if err != nil {
		log.Fatal(err)
	}

	files, err := analyzer.AnalyzeFromFile(ctx, rc)
	if err != nil {
		log.Fatal(err)
	}
	analyzer.GetOS(files)
	analyzer.GetPackages(files)
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
