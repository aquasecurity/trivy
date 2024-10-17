//go:build mage_helm

package main

import (
	"fmt"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
)

const chartFile = "./helm/trivy/Chart.yaml"

func main() {
	trivyVersion, err := version()
	if err != nil {
		log.Fatalf("could not determine Trivy version: %v", err)
	}
	input, err := os.ReadFile(chartFile)
	if err != nil {
		log.Fatalf("could not find helm chart %s: %v", chartFile, err)
	}
	jsonData := map[string]interface{}{}
	if err := yaml.Unmarshal(input, &jsonData); err != nil {
		log.Fatalf("could not unmarshal helm chart %s: %v", chartFile, err)
	}
	currentAppVersion, ok := jsonData["appVersion"].(string)
	if !ok {
		log.Fatalf("could not determine current app version")
	}
	currentHelmVersion, ok := jsonData["version"].(string)
	if !ok {
		log.Fatalf("could not determine current helm version")
	}
	newHelmVersion := newHelmVersion(currentHelmVersion, currentAppVersion, trivyVersion)

	log.Printf("Current helm version %q with Trivy %q will bump up %q with Trivy %q",
		currentHelmVersion, currentAppVersion, newHelmVersion, trivyVersion)

	err = sh.Run("sed", "-i", "-e",
		fmt.Sprintf("s/appVersion: %s/appVersion: %s/g", currentAppVersion, trivyVersion), chartFile)
	if err != nil {
		log.Fatalf("could not install helm chart: %v", err)
	}

	err = sh.Run("sed", "-i", "-e",
		fmt.Sprintf("s/version: %s/version: %s/g", currentHelmVersion, trivyVersion), chartFile)
	if err != nil {
		log.Fatalf("could not install helm chart: %v", err)
	}
}

func newHelmVersion(currentHelm, currentApp, newTrivy string) string {
	ch := strings.Split(currentHelm, ".")
	ca := strings.Split(newTrivy, ".")
	return ""
}
