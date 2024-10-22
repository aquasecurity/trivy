//go:build mage_helm

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aquasecurity/go-version/pkg/semver"

	"github.com/magefile/mage/sh"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

const chartFile = "./helm/trivy/Chart.yaml"

func main() {
	trivyVersion, err := version()
	if err != nil {
		log.Fatalf("could not determine Trivy version: %v", err)
	}

	newHelmVersion, err := bumpHelmChart(chartFile, trivyVersion)
	if err != nil {
		log.Fatalf("could not bump Trivy version to %q: %v", trivyVersion, err)
	}

	log.Printf("Current helm version will bump up %q with Trivy %q", newHelmVersion, trivyVersion)

	newBranch := fmt.Sprintf("ci/helm-chart/bump-trivy-to-%s", trivyVersion)
	title := fmt.Sprintf("ci(helm): bump Trivy version to %s for Trivy Helm Chart %s", trivyVersion, newHelmVersion)
	description := fmt.Sprintf("This PR bumps Trivy up to the %s version for the Trivy Helm chart %s.",
		trivyVersion, newHelmVersion)

	cmds := [][]string{
		[]string{"git", "switch", "-c", newBranch},
		[]string{"git", "add", chartFile},
		[]string{"git", "commit", "-m", title},
		[]string{"git", "push", "origin", newBranch},
		[]string{"gh", "pr", "create", "--base", "main", "--head", newBranch, "--title", title, "--body", description, "--repo", "$GITHUB_REPOSITORY"},
	}

	if err := runShCommands(cmds); err != nil {
		log.Fatal(err)
	}
	log.Print("Successfully created PR with a new helm version")
}

type Chart struct {
	Version    string `yaml:"version"`
	AppVersion string `yaml:"appVersion"`
}

// bumpHelmChart bumps up helm and trivy versions inside a file (Chart.yaml)
// it returns a new helm version and error
func bumpHelmChart(filename, trivyVersion string) (string, error) {
	input, err := os.ReadFile(filename)
	if err != nil {
		return "", xerrors.Errorf("could not read file %q: %w", filename, err)
	}
	currentHelmChart := &Chart{}
	if err := yaml.Unmarshal(input, currentHelmChart); err != nil {
		return "", xerrors.Errorf("could not unmarshal helm chart %q: %w", filename, err)
	}

	newHelmVersion, err := buildNewHelmVersion(currentHelmChart.Version, currentHelmChart.AppVersion, trivyVersion)
	if err != nil {
		return "", xerrors.Errorf("could not build new helm version: %v", err)
	}
	cmds := [][]string{
		[]string{"sed", "-i", "-e", fmt.Sprintf("s/appVersion: %s/appVersion: %s/g", currentHelmChart.AppVersion, trivyVersion), filename},
		[]string{"sed", "-i", "-e", fmt.Sprintf("s/version: %s/version: %s/g", currentHelmChart.Version, newHelmVersion), filename},
	}

	if err := runShCommands(cmds); err != nil {
		return "", xerrors.Errorf("could not update Helm Chart %q: %w", newHelmVersion, err)
	}
	return newHelmVersion, nil
}

func runShCommands(cmds [][]string) error {
	for _, cmd := range cmds {
		if err := sh.Run(cmd[0], cmd[1:]...); err != nil {
			return xerrors.Errorf("failed to run %v: %w", cmd, err)
		}
	}
	return nil
}

func buildNewHelmVersion(currentHelm, currentTrivy, newTrivy string) (string, error) {
	currentHelmVersion, err := semver.Parse(currentHelm)
	if err != nil {
		return "", xerrors.Errorf("could not parse current helm version: %w", err)
	}

	currentTrivyVersion, err := semver.Parse(currentTrivy)
	if err != nil {
		return "", xerrors.Errorf("could not parse current trivy version: %w", err)
	}

	newTrivyVersion, err := semver.Parse(newTrivy)
	if err != nil {
		return "", xerrors.Errorf("could not parse new trivy version: %w", err)
	}

	if newTrivyVersion.Major().Compare(currentTrivyVersion.Major()) > 0 {
		return currentHelmVersion.IncMajor().String(), nil
	}

	if newTrivyVersion.Minor().Compare(currentTrivyVersion.Minor()) > 0 {
		return currentHelmVersion.IncMinor().String(), nil
	}

	return currentHelmVersion.IncPatch().String(), nil
}
