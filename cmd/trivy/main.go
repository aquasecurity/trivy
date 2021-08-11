package main

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/app"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
	app.Version = version
	if err := commands.NewApp().Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
