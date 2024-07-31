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

	flagsMetadata := buildFlagsTree()
	genMarkdown(flagsMetadata, -1, f)

	f.WriteString(footer)
	return nil
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

func buildFlagsTree() map[string]any {
	details := getFlagDetails("Global", flag.NewGlobalFlagGroup().Flags())
	details = append(details, getFlagDetails("Report", flag.NewReportFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Image", flag.NewImageFlagGroup().Flags())...)
	details = append(details, getFlagDetails("DB", flag.NewDBFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Cache", flag.NewCacheFlagGroup().Flags())...)
	details = append(details, getFlagDetails("License", flag.NewLicenseFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Misconfiguration", flag.NewMisconfFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Scan", flag.NewScanFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Module", flag.NewModuleFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Client/Server", flag.NewClientFlags().Flags())...)
	details = append(details, getFlagDetails("Registry", flag.NewRegistryFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Rego", flag.NewRegoFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Secret", flag.NewSecretFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Vulnerability", flag.NewVulnerabilityFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Kubernetes", flag.NewK8sFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Repository", flag.NewRepoFlagGroup().Flags())...)
	details = append(details, getFlagDetails("Clean", flag.NewCleanFlagGroup().Flags())...)

	res := map[string]any{}
	for _, m := range details {
		addToMap(res, strings.Split(m.configName, "."), m)
	}
	return res
}

func genMarkdown(m map[string]any, indent int, w *os.File) {
	// Extract and sort keys
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	if indent == -1 {
		for _, key := range keys {
			w.WriteString("## " + key + " options\n\n")
			w.WriteString("```yaml\n")
			genMarkdown(m[key].(map[string]any), 0, w)
			w.WriteString("```\n\n")
		}
		return
	}
	indentation := strings.Repeat("  ", indent)

	for _, key := range keys {
		switch v := m[key].(type) {
		case map[string]any:
			fmt.Fprintf(w, "%s%s:\n", indentation, key)
			genMarkdown(v, indent+1, w)
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
