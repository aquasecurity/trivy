package main

import (
	l "log"
	"os"

	"github.com/aquasecurity/trivy/pkg"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
	app := pkg.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		if log.Logger != nil {
			log.Fatal(err)
		}
		l.Fatal(err)
	}
}
