package types

type Source string

const (
	SourceDockerfile Source = "dockerfile"
	SourceKubernetes Source = "kubernetes"
	// Deprecated: use "kubernetes" instead
	SourceRbac Source = "rbac"
	// Deprecated: use "cloud" instead
	SourceDefsec    Source = "defsec"
	SourceCloud     Source = "cloud"
	SourceYAML      Source = "yaml"
	SourceJSON      Source = "json"
	SourceTOML      Source = "toml"
	SourceTerraform Source = "terraform"
)
