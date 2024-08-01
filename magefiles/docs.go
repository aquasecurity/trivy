//go:build mage_docs

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra/doc"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	title       = "Config file"
	description = "Trivy can be customized by tweaking a `trivy.yaml` file.\n" +
		"The config path can be overridden by the `--config` flag.\n\n" +
		"An example is [here][example].\n"
	footer = "[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml"
)

// Generate CLI references
func main() {
	// Set a dummy path for the documents
	flag.CacheDirFlag.Default = "/path/to/cache"
	flag.ModuleDirFlag.Default = "$HOME/.trivy/modules"

	// Set a dummy path not to load plugins
	os.Setenv("XDG_DATA_HOME", os.TempDir())

	cmd := commands.NewApp()
	cmd.DisableAutoGenTag = true
	if err := doc.GenMarkdownTree(cmd, "./docs/docs/references/configuration/cli"); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
	if err := generateConfigDocs("./docs/docs/references/configuration/config-file.md"); err != nil {
		log.Fatal("Fatal error in config file generation", log.Err(err))
	}
}

// generateConfigDocs creates custom markdown output.
func generateConfigDocs(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("# " + title + "\n\n")
	f.WriteString(description + "\n")

	flagsTree := buildFlagsTree()

	// -1 - is a level for title(section)
	generateMarkdownByFlagDetailsTree(flagsTree, -1, f)

	f.WriteString(footer)
	return nil
}

func generateMarkdownByFlagDetailsTree(flagTree map[string]any, indent int, w *os.File) {
	// Extract and sort keys
	keys := make([]string, 0, len(flagTree))
	for key := range flagTree {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	if indent == -1 {
		for _, key := range keys {
			w.WriteString("## " + key + " options\n\n")
			w.WriteString("```yaml\n")
			generateMarkdownByFlagDetailsTree(flagTree[key].(map[string]any), 0, w)
			w.WriteString("```\n\n")
		}
		return
	}
	indentation := strings.Repeat("  ", indent)

	for _, key := range keys {
		switch v := flagTree[key].(type) {
		case map[string]any:
			fmt.Fprintf(w, "%s%s:\n", indentation, key)
			generateMarkdownByFlagDetailsTree(v, indent+1, w)
		case *flagDetails:
			if v.name != "" {
				fmt.Fprintf(w, "%s# Same as '--%s'\n", indentation, v.name)
			}
			fmt.Fprintf(w, "%s# Default is %v\n", indentation, v.defaultValue)
			if len(v.example) > 1 {
				fmt.Fprintf(w, "%s%s:\n", indentation, key)
				for _, line := range v.example {
					fmt.Fprintf(w, "%s - %s\n", indentation, line)
				}
			} else {
				fmt.Fprintf(w, "%s%s: %s\n\n", indentation, key, v.example[0])
			}
		}
	}
}

type flagDetails struct {
	name         string
	configName   string
	defaultValue any
	example      []string
}

func getFlagDetails(section string, flagGroup []flag.Flagger) []*flagDetails {
	result := []*flagDetails{}
	for _, flg := range flagGroup {
		if flg == nil {
			continue
		}
		var defaultValue any
		var example []string

		switch p := flg.GetDefaultValue().(type) {
		case string:
			defaultValue = lo.Ternary(len(p) > 0, p, "empty")
			example = append(example, lo.Ternary(len(p) > 0, p, ""))
		case []string:
			if len(p) > 0 {
				defaultValue = strings.Join(p, ", ")
				for _, line := range p {
					example = append(example, line)
				}
			}
		}
		if defaultValue == nil {
			defaultValue = flg.GetDefaultValue()
		}
		if len(example) == 0 {
			example = append(example, fmt.Sprintf("%v", defaultValue))
		}
		result = append(result, &flagDetails{
			name:         flg.GetName(),
			configName:   section + "." + flg.GetConfigName(),
			defaultValue: defaultValue,
			example:      example,
		})
	}
	return result
}

func buildFlagsTree() map[string]any {
	var allFlags = map[string][]flag.Flagger{
		"Global":           flag.NewGlobalFlagGroup().Flags(),
		"Report":           flag.NewReportFlagGroup().Flags(),
		"Image":            flag.NewImageFlagGroup().Flags(),
		"DB":               flag.NewDBFlagGroup().Flags(),
		"Cache":            flag.NewCacheFlagGroup().Flags(),
		"License":          flag.NewLicenseFlagGroup().Flags(),
		"Misconfiguration": flag.NewMisconfFlagGroup().Flags(),
		"Scan":             flag.NewScanFlagGroup().Flags(),
		"Module":           flag.NewModuleFlagGroup().Flags(),
		"Registry":         flag.NewRegistryFlagGroup().Flags(),
		"Rego":             flag.NewRegoFlagGroup().Flags(),
		"Secret":           flag.NewSecretFlagGroup().Flags(),
		"Vulnerability":    flag.NewVulnerabilityFlagGroup().Flags(),
		"Kubernetes":       flag.NewK8sFlagGroup().Flags(),
		"Repository":       flag.NewRepoFlagGroup().Flags(),
		"Clean":            flag.NewCleanFlagGroup().Flags(),
		"Cloud":            flag.NewAWSFlagGroup().Flags(),
	}
	// remoteFlags should contain Client and Server flags.
	// NewClientFlags doesn't initialize `Listen` field
	remoteFlags := flag.NewClientFlags()
	remoteFlags.Listen = flag.ServerListenFlag.Clone()
	allFlags["Client/Server"] = remoteFlags.Flags()

	var details []*flagDetails
	for k, v := range allFlags {
		details = append(details, getFlagDetails(k, v)...)
	}
	res := map[string]any{}
	for _, m := range details {
		addToMap(res, strings.Split(m.configName, "."), m)
	}
	return res
}

func addToMap(m map[string]any, parts []string, value *flagDetails) {
	if len(parts) == 0 {
		return
	}
	if len(parts) == 1 {
		m[parts[0]] = value
		return
	}
	if _, exists := m[parts[0]]; !exists {
		m[parts[0]] = make(map[string]any)
	}
	subMap, ok := m[parts[0]].(map[string]any)
	if !ok {
		subMap = make(map[string]any)
		m[parts[0]] = subMap
	}
	addToMap(subMap, parts[1:], value)
}
