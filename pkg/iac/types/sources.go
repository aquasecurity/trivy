package types

type Source string

const (
	SourceDockerfile Source = "dockerfile"
	SourceKubernetes Source = "kubernetes"
	SourceRbac       Source = "rbac"   // deprecated - please use "kubernetes" instead
	SourceDefsec     Source = "defsec" // deprecated - please use "cloud" instead
	SourceCloud      Source = "cloud"
	SourceYAML       Source = "yaml"
	SourceJSON       Source = "json"
	SourceTOML       Source = "toml"
)
