package types

type Source string

const (
	SourceTerraform      Source = "terraform"
	SourceDockerfile     Source = "dockerfile"
	SourceKubernetes     Source = "kubernetes"
	SourceCloudFormation Source = "cloudformation"
	SourceAnsible        Source = "ansible"
	SourceDefsec         Source = "defsec"
)
