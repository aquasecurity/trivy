package main

import (
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
	app := commands.NewApp(version)
	if err := app.Execute(); err != nil {
		log.Fatal(err)
	}
}
