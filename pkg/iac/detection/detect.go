package detection

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/snapshot"
	"github.com/aquasecurity/trivy/pkg/log"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type FileType string

const (
	FileTypeCloudFormation        FileType = "cloudformation"
	FileTypeTerraform             FileType = "terraform"
	FileTypeTerraformPlanJSON     FileType = "terraformplan-json"
	FileTypeTerraformPlanSnapshot FileType = "terraformplan-snapshot"
	FileTypeDockerfile            FileType = "dockerfile"
	FileTypeKubernetes            FileType = "kubernetes"
	FileTypeRbac                  FileType = "rbac"
	FileTypeYAML                  FileType = "yaml"
	FileTypeTOML                  FileType = "toml"
	FileTypeJSON                  FileType = "json"
	FileTypeHelm                  FileType = "helm"
	FileTypeAzureARM              FileType = "azure-arm"
	FileTypeAnsible               FileType = "ansible"
)

var matchers = make(map[FileType]func(name string, r io.ReadSeeker) bool)

func init() {
	matchers[FileTypeJSON] = detectJSON
	matchers[FileTypeYAML] = detectYAML
	matchers[FileTypeHelm] = detectHelm
	matchers[FileTypeTOML] = detectTOML
	matchers[FileTypeTerraform] = detectTerraform
	matchers[FileTypeTerraformPlanJSON] = detectTerraformPlanJSON
	matchers[FileTypeTerraformPlanSnapshot] = detectTerraformPlanSnapshot
	matchers[FileTypeCloudFormation] = detectCloudFormation
	matchers[FileTypeAzureARM] = detectAzureARM
	matchers[FileTypeDockerfile] = detectDockerfile
	matchers[FileTypeKubernetes] = detectKubernetes
	matchers[FileTypeAnsible] = detectAnsible
}

func detectJSON(name string, r io.ReadSeeker) bool {
	if !isJSON(name) {
		return false
	}
	if resetReader(r) == nil {
		return true
	}

	b, err := io.ReadAll(r)
	return err == nil && json.Valid(b)
}

func detectYAML(name string, r io.ReadSeeker) bool {
	if !isYAML(name) {
		return false
	}
	if resetReader(r) == nil {
		return true
	}

	var content any
	return yaml.NewDecoder(r).Decode(&content) == nil
}

func detectHelm(name string, r io.ReadSeeker) bool {
	helmFiles := []string{"Chart.yaml", ".helmignore", "values.schema.json", "NOTES.txt"}
	for _, expected := range helmFiles {
		if strings.HasSuffix(name, expected) {
			return true
		}
	}
	helmFileExtensions := []string{".yml", ".yaml", ".tpl"}
	ext := filepath.Ext(filepath.Base(name))
	for _, expected := range helmFileExtensions {
		if strings.EqualFold(ext, expected) {
			return true
		}
	}
	return IsHelmChartArchive(name, r)
}

func detectTOML(name string, _ io.ReadSeeker) bool {
	ext := filepath.Ext(filepath.Base(name))
	return strings.EqualFold(ext, ".toml")
}

func detectTerraform(name string, _ io.ReadSeeker) bool {
	return IsTerraformFile(name)
}

func detectTerraformPlanJSON(name string, r io.ReadSeeker) bool {
	if IsType(name, r, FileTypeJSON) {
		if resetReader(r) == nil {
			return false
		}

		contents := make(map[string]any)
		err := json.NewDecoder(r).Decode(&contents)
		if err != nil {
			return false
		}

		for _, k := range []string{"terraform_version", "format_version"} {
			if _, ok := contents[k]; !ok {
				return false
			}
		}

		return true
	}
	return false
}

func detectTerraformPlanSnapshot(_ string, r io.ReadSeeker) bool {
	return snapshot.IsPlanSnapshot(r)
}

func detectCloudFormation(name string, r io.ReadSeeker) bool {
	sniff := struct {
		Resources map[string]map[string]any `json:"Resources" yaml:"Resources"`
	}{}

	switch {
	case IsType(name, r, FileTypeYAML):
		if resetReader(r) == nil {
			return false
		}
		if err := yaml.NewDecoder(r).Decode(&sniff); err != nil {
			return false
		}
	case IsType(name, r, FileTypeJSON):
		if resetReader(r) == nil {
			return false
		}
		if err := json.NewDecoder(r).Decode(&sniff); err != nil {
			return false
		}
	default:
		return false
	}

	return sniff.Resources != nil
}

func detectAzureARM(_ string, r io.ReadSeeker) bool {
	if resetReader(r) == nil {
		return false
	}

	sniff := struct {
		Schema     string         `json:"$schema"`
		Handler    string         `json:"handler"`
		Parameters map[string]any `json:"parameters"`
		Resources  any            `json:"resources"`
	}{}

	data, err := io.ReadAll(r)
	if err != nil {
		return false
	}

	if err := json.Unmarshal(xjson.ToRFC8259(data), &sniff); err != nil {
		return false
	}

	// schema is required https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/syntax
	if !strings.HasPrefix(sniff.Schema, "https://schema.management.azure.com/schemas") {
		return false
	}

	// skip CreateUiDefinition
	// https://learn.microsoft.com/en-us/azure/azure-resource-manager/managed-applications/create-uidefinition-overview
	if sniff.Handler != "" {
		return false
	}

	hasResources := false
	if sniff.Resources != nil {
		switch resources := sniff.Resources.(type) {
		case []any:
			hasResources = len(resources) > 0
		case map[string]any:
			hasResources = len(resources) > 0
		}
	}

	return len(sniff.Parameters) > 0 || hasResources
}

func detectDockerfile(name string, _ io.ReadSeeker) bool {
	requiredFiles := []string{"Dockerfile", "Containerfile"}
	for _, requiredFile := range requiredFiles {
		base := filepath.Base(name)
		ext := filepath.Ext(base)
		if strings.TrimSuffix(base, ext) == requiredFile {
			return true
		}
		if strings.EqualFold(ext, "."+requiredFile) {
			return true
		}
	}
	return false
}

func detectKubernetes(name string, r io.ReadSeeker) bool {
	if !IsType(name, r, FileTypeYAML) && !IsType(name, r, FileTypeJSON) {
		return false
	}
	if resetReader(r) == nil {
		return false
	}

	expectedProperties := []string{"apiVersion", "kind", "metadata"}

	if IsType(name, r, FileTypeJSON) {
		if resetReader(r) == nil {
			return false
		}

		var result map[string]any
		if err := json.NewDecoder(r).Decode(&result); err != nil {
			return false
		}

		for _, expected := range expectedProperties {
			if _, ok := result[expected]; !ok {
				return false
			}
		}
		return true
	}

	// at this point, we need to inspect bytes
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return false
	}
	data := buf.Bytes()

	marker := []byte("\n---\n")
	altMarker := []byte("\r\n---\r\n")
	if bytes.Contains(data, altMarker) {
		marker = altMarker
	}

	for partial := range bytes.SplitSeq(data, marker) {
		var result map[string]any
		if err := yaml.Unmarshal(partial, &result); err != nil {
			continue
		}
		match := true
		for _, expected := range expectedProperties {
			if _, ok := result[expected]; !ok {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}

func detectAnsible(name string, _ io.ReadSeeker) bool {
	return filepath.Base(name) == "ansible.cfg" ||
		slices.Contains([]string{"", ".yml", ".yaml", ".json", ".ini"}, filepath.Ext(name))
}

func IsTerraformFile(path string) bool {
	if strings.HasSuffix(path, filepath.ToSlash(".terraform/modules/modules.json")) {
		return true
	}

	for _, ext := range []string{".tf", ".tf.json", ".tfvars", ".tofu", ".tofu.json"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

func IsType(name string, r io.ReadSeeker, t FileType) bool {
	r = ensureSeeker(r)
	f, ok := matchers[t]
	if !ok {
		return false
	}
	return f(name, r)
}

func GetTypes(name string, r io.ReadSeeker) []FileType {
	var matched []FileType
	r = ensureSeeker(r)
	for check, f := range matchers {
		if f(name, r) {
			matched = append(matched, check)
		}
		resetReader(r)
	}
	return matched
}

func ensureSeeker(r io.Reader) io.ReadSeeker {
	if r == nil {
		return nil
	}
	if seeker, ok := r.(io.ReadSeeker); ok {
		return seeker
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err == nil {
		return bytes.NewReader(buf.Bytes())
	}

	return nil
}

func resetReader(r io.Reader) io.ReadSeeker {
	if r == nil {
		return nil
	}
	if seeker, ok := r.(io.ReadSeeker); ok {
		_, _ = seeker.Seek(0, 0)
		return seeker
	}
	return ensureSeeker(r)
}

func isJSON(name string) bool {
	ext := filepath.Ext(name)
	return strings.EqualFold(ext, ".json")
}
func isYAML(name string) bool {
	ext := filepath.Ext(name)
	return strings.EqualFold(ext, ".yaml") || strings.EqualFold(ext, ".yml")
}

func IsFileMatchesSchemas(schemas map[string]*gojsonschema.Schema, typ FileType, name string, r io.ReadSeeker) bool {
	defer resetReader(r)

	var l gojsonschema.JSONLoader
	switch {
	case typ == FileTypeJSON && isJSON(name):
		b, err := io.ReadAll(r)
		if err != nil {
			return false
		}
		l = gojsonschema.NewBytesLoader(b)
	case typ == FileTypeYAML && isYAML(name):
		var content any
		if err := yaml.NewDecoder(r).Decode(&content); err != nil {
			return false
		}
		l = gojsonschema.NewGoLoader(content)
	default:
		return false
	}

	for schemaPath, schema := range schemas {
		if res, err := schema.Validate(l); err == nil && res.Valid() {
			log.Debug("File matched schema", log.FilePath(name), log.String("schema_path", schemaPath))
			return true
		}
	}
	return false
}
