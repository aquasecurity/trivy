package main

import (
	"os"

	"github.com/aquasecurity/trivy/internal"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
	app := internal.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
