//go:build mage_docs

package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

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
	genMarkdown(flagsMetadata, 0, f)

	f.WriteString(footer)
	return nil
}

type flagMetadata struct {
	name         string
	configName   string
	defaultValue any
}

func getFlagMetadata(flagGroup any) []*flagMetadata {
	result := []*flagMetadata{}
	val := reflect.ValueOf(flagGroup)
	for i := 0; i < val.NumField(); i++ {
		p, ok := val.Field(i).Interface().(*flag.Flag[string])
		if !ok {
			continue
		}
		result = append(result, &flagMetadata{
			name:         p.Name,
			configName:   p.ConfigName,
			defaultValue: p.Default,
		})
	}
	return result
}

func addToMap(m map[string]any, parts []string, defaultValue any) {
	if len(parts) == 0 {
		return
	}
	if len(parts) == 1 {
		m[parts[0]] = defaultValue
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

	addToMap(subMap, parts[1:], defaultValue)
}

func buildFlagsTree() map[string]any {
	res := map[string]any{}
	metadata := getFlagMetadata(*flag.NewImageFlagGroup())
	metadata = append(metadata, getFlagMetadata(*flag.NewCacheFlagGroup())...)
	metadata = append(metadata, getFlagMetadata(*flag.NewReportFlagGroup())...)

	for _, m := range metadata {
		addToMap(res, strings.Split(m.configName, "."), m.defaultValue)
	}
	return res
}

var caser = cases.Title(language.English)

func genMarkdown(m map[string]any, indent int, w *os.File) {
	indentation := strings.Repeat("  ", indent)
	for key, value := range m {
		if indent == 0 {
			w.WriteString("## " + caser.String(key) + " options\n\n")
			w.WriteString("```yaml\n")
		}

		switch v := value.(type) {
		case map[string]any:
			w.WriteString(fmt.Sprintf("%s%s:\n", indentation, key))
			genMarkdown(v, indent+1, w)
		default:
			w.WriteString(fmt.Sprintf("%s%s: %v\n", indentation, key, v))
		}
		if indent == 0 {
			w.WriteString("```\n\n")
		}
	}
}
