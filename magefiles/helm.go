//go:build mage_helm

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

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
	input, err := os.ReadFile(chartFile)
	if err != nil {
		log.Fatalf("could not find helm chart %s: %v", chartFile, err)
	}
	yamlData := map[string]interface{}{}
	if err := yaml.Unmarshal(input, &yamlData); err != nil {
		log.Fatalf("could not unmarshal helm chart %s: %v", chartFile, err)
	}
	currentTrivyVersion, ok := yamlData["appVersion"].(string)
	if !ok {
		log.Fatalf("could not determine current app version")
	}
	currentHelmVersion, ok := yamlData["version"].(string)
	if !ok {
		log.Fatalf("could not determine current helm version")
	}
	newHelmVersion := buildNewHelmVersion(currentHelmVersion, currentTrivyVersion, trivyVersion)

	log.Printf("Current helm version %q with Trivy %q will bump up %q with Trivy %q",
		currentHelmVersion, currentTrivyVersion, newHelmVersion, trivyVersion)

	newBranch := fmt.Sprintf("ci/helm-chart/bump-trivy-to-%s", trivyVersion)
	title := fmt.Sprintf("ci(helm): bump Trivy version to %s for Trivy Helm Chart %s", trivyVersion, newHelmVersion)
	description := fmt.Sprintf("This PR bumps Trivy up to the %s version for the Trivy Helm chart %s.",
		trivyVersion, newHelmVersion)

	cmds := [][]string{
		[]string{"sed", "-i", "-e", fmt.Sprintf("s/appVersion: %s/appVersion: %s/g", currentTrivyVersion, trivyVersion), chartFile},
		[]string{"sed", "-i", "-e", fmt.Sprintf("s/version: %s/version: %s/g", currentHelmVersion, newHelmVersion), chartFile},
		[]string{"git", "switch", "-c", newBranch},
		[]string{"git", "add", "./helm/trivy/Chart.yaml"},
		[]string{"git", "commit", "-m", title},
		[]string{"git", "push", "origin", newBranch},
		[]string{"gh", "pr", "create", "--base", "main", "--head", newBranch, "--title", title, "--body", description, "--repo", "$GITHUB_REPOSITORY"},
	}

	if err := runShCommands(cmds); err != nil {
		log.Fatal(err)
	}
	log.Print("Successfully created PR with a new helm version")
}

func runShCommands(cmds [][]string) error {
	for _, cmd := range cmds {
		if err := sh.Run(cmd[0], cmd[1:]...); err != nil {
			return xerrors.Errorf("failed to run %v: %w", cmd, err)
		}
	}
	return nil
}

func splitVersion(version string) []int {
	items := strings.Split(version, ".")
	result := make([]int, len(items))
	for i, item := range items {
		result[i], _ = strconv.Atoi(item)
	}
	return result
}

func buildNewHelmVersion(currentHelm, currentTrivy, newTrivy string) string {
	ch := splitVersion(currentHelm)
	ct := splitVersion(currentTrivy)
	tr := splitVersion(newTrivy)

	if len(ch) != len(ct) || len(ch) != len(tr) || len(ch) != 3 {
		log.Fatalf("invalid version lengths for %q, %q and %q", currentHelm, currentTrivy, newTrivy)
	}

	n := len(ch)
	res := make([]string, n)
	if tr[0] != ct[0] {
		res[0] = strconv.Itoa(tr[0])
		res[1] = strconv.Itoa(tr[1])
		res[2] = "0"
		return strings.Join(res, ".")
	}

	res[0] = strconv.Itoa(tr[0])
	if tr[1] != ct[1] {
		res[1] = strconv.Itoa(ch[1] + tr[1] - ct[1])
		res[2] = "0"
	} else {
		res[1] = strconv.Itoa(ch[1])
		res[2] = strconv.Itoa(ch[2] + tr[2] - ct[2])
	}
	return strings.Join(res, ".")
}
