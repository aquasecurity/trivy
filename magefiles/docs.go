//go:build mage_docs

package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

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

func getFlagDetails(section string, flagGroup any) []*flagDetails {
	result := []*flagDetails{}
	val := reflect.ValueOf(flagGroup)
	for i := 0; i < val.NumField(); i++ {
		var name, configName string
		var defaultValue any
		var example []string
		switch p := val.Field(i).Interface().(type) {
		case *flag.Flag[int]:
			name = p.Name
			configName = p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[bool]:
			if p == nil {
				continue
			}
			name = p.Name
			configName = p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[string]:
			if p == nil {
				continue
			}
			name = p.Name
			configName = p.ConfigName
			defaultValue = lo.Ternary(len(p.Default) > 0, p.Default, "empty")
			example = append(example, lo.Ternary(len(p.Default) > 0, p.Default, ""))
		case *flag.Flag[[]string]:
			name = p.Name
			configName = p.ConfigName
			defaultValue = p.Default
			if len(p.Default) > 0 {
				for _, line := range p.Default {
					example = append(example, line)
				}
			}
		case *flag.Flag[time.Duration]:
			name = p.Name
			configName = p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[float64]:
			name = p.Name
			configName = p.ConfigName
			defaultValue = p.Default
		default:
			continue
		}
		if len(example) == 0 {
			example = append(example, fmt.Sprintf("%v", defaultValue))
		}
		result = append(result, &flagDetails{
			name:         name,
			configName:   section + "." + configName,
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
	res := map[string]any{}
	details := getFlagDetails("Global", *flag.NewGlobalFlagGroup())
	details = append(details, getFlagDetails("Report", *flag.NewReportFlagGroup())...)
	details = append(details, getFlagDetails("Image", *flag.NewImageFlagGroup())...)
	details = append(details, getFlagDetails("DB", *flag.NewDBFlagGroup())...)
	details = append(details, getFlagDetails("Cache", *flag.NewCacheFlagGroup())...)
	details = append(details, getFlagDetails("License", *flag.NewLicenseFlagGroup())...)
	details = append(details, getFlagDetails("Misconfiguration", *flag.NewMisconfFlagGroup())...)
	details = append(details, getFlagDetails("Scan", *flag.NewScanFlagGroup())...)
	details = append(details, getFlagDetails("Module", *flag.NewModuleFlagGroup())...)
	details = append(details, getFlagDetails("Client/Server", *flag.NewClientFlags())...)
	details = append(details, getFlagDetails("Registry", *flag.NewRegistryFlagGroup())...)
	details = append(details, getFlagDetails("Rego", *flag.NewRegoFlagGroup())...)
	details = append(details, getFlagDetails("Secret", *flag.NewSecretFlagGroup())...)
	details = append(details, getFlagDetails("Vulnerability", *flag.NewVulnerabilityFlagGroup())...)
	details = append(details, getFlagDetails("Kubernetes", *flag.NewK8sFlagGroup())...)
	details = append(details, getFlagDetails("Repository", *flag.NewRepoFlagGroup())...)
	details = append(details, getFlagDetails("Clean", *flag.NewCleanFlagGroup())...)

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
			fmt.Fprintf(w, "%s# Same as '--%s'\n", indentation, v.name)
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
