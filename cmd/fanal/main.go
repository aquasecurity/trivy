package main

import (
	"flag"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/knqyf263/fanal/analyzer"
	_ "github.com/knqyf263/fanal/analyzer/os/alpine"
	_ "github.com/knqyf263/fanal/analyzer/pkg/apk"
)

func main() {
	tarPath := flag.String("f", "-", "layer.tar path")
	flag.Parse()
	rc, err := openStream(*tarPath)
	if err != nil {
		log.Fatal(err)
	}

	files, _ := analyzer.Analyze(rc)
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
