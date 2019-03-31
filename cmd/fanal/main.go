package main

import (
	"log"
	"os"

	"github.com/knqyf263/fanal/analyzer"
	_ "github.com/knqyf263/fanal/analyzer/os/alpine"
	_ "github.com/knqyf263/fanal/analyzer/pkg/apk"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	files, _ := analyzer.Analyze(dir)
	analyzer.GetOS(files)
	analyzer.GetPackages(files)
}
