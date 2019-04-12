package main

import (
	"log"
	"os"

	"github.com/knqyf263/trivy/pkg/logger"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/scanner/composer"
	"github.com/knqyf263/trivy/pkg/scanner/gem"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := logger.InitLogger(); err != nil {
		return err
	}

	//fileName := os.Args[1]
	//fileName := "Gemfile.lock"
	fileName := "composer.lock"
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	switch fileName {
	case "Gemfile.lock":
		scanner.Register(gem.NewGemScanner(f))
	case "composer.lock":
		scanner.Register(composer.NewComposerScanner(f))
	}

	if err = scanner.Scan(); err != nil {
		return err
	}

	return nil
}
