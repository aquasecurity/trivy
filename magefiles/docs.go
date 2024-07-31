//go:build mage_docs

package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

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

type flagMetadata struct {
	name         string
	configName   string
	defaultValue any
}

func getFlagMetadata(section string, flagGroup any) []*flagMetadata {
	result := []*flagMetadata{}
	val := reflect.ValueOf(flagGroup)
	for i := 0; i < val.NumField(); i++ {
		var name, configName string
		var defaultValue any
		switch p := val.Field(i).Interface().(type) {
		case *flag.Flag[int]:
			name = p.Name
			configName = section + "." + p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[bool]:
			if p == nil {
				continue
			}
			name = p.Name
			configName = section + "." + p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[string]:
			name = p.Name
			configName = section + "." + p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[[]string]:
			name = p.Name
			configName = section + "." + p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[time.Duration]:
			name = p.Name
			configName = section + "." + p.ConfigName
			defaultValue = p.Default
		case *flag.Flag[float64]:
			name = p.Name
			configName = section + "." + p.ConfigName
			defaultValue = p.Default
		default:
			continue
		}
		result = append(result, &flagMetadata{
			name:         name,
			configName:   configName,
			defaultValue: defaultValue,
		})
	}
	return result
}

func addToMap(m map[string]any, parts []string, value *flagMetadata) {
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
	metadata := getFlagMetadata("Global", *flag.NewGlobalFlagGroup())
	metadata = append(metadata, getFlagMetadata("Report", *flag.NewReportFlagGroup())...)
	metadata = append(metadata, getFlagMetadata("Image", *flag.NewImageFlagGroup())...)
	metadata = append(metadata, getFlagMetadata("Cache", *flag.NewCacheFlagGroup())...)
	for _, m := range metadata {
		addToMap(res, strings.Split(m.configName, "."), m)
	}
	return res
}

func genMarkdown(m map[string]any, indent int, w *os.File) {
	if indent == -1 {
		for k, v := range m {
			w.WriteString("## " + k + " options\n\n")
			w.WriteString("```yaml\n")
			genMarkdown(v.(map[string]any), 0, w)
			w.WriteString("```\n\n")
		}
		return
	}
	indentation := strings.Repeat("  ", indent)

	// Extract and sort keys
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		switch v := m[key].(type) {
		case map[string]any:
			fmt.Fprintf(w, "%s%s:\n", indentation, key)
			genMarkdown(v, indent+1, w)
		case *flagMetadata:
			fmt.Fprintf(w, "%s# Same as '--%s'\n", indentation, v.name)
			fmt.Fprintf(w, "%s# Default is %v\n", indentation, v.defaultValue)
			fmt.Fprintf(w, "%s%s: %+v\n\n", indentation, key, v.defaultValue)
		}
	}
}
