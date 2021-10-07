package types

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 2
)

const (
	// Programming language dependencies
	Bundler    = "bundler"
	GemSpec    = "gemspec"
	Cargo      = "cargo"
	Composer   = "composer"
	Npm        = "npm"
	NuGet      = "nuget"
	Pip        = "pip"
	Pipenv     = "pipenv"
	Poetry     = "poetry"
	PythonPkg  = "python-pkg"
	NodePkg    = "node-pkg"
	Yarn       = "yarn"
	Jar        = "jar"
	GoBinary   = "gobinary"
	GoMod      = "gomod"
	JavaScript = "javascript"

	// Config files
	YAML           = "yaml"
	JSON           = "json"
	TOML           = "toml"
	Dockerfile     = "dockerfile"
	HCL            = "hcl"
	Terraform      = "terraform"
	Kubernetes     = "kubernetes"
	CloudFormation = "cloudformation"
	Ansible        = "ansible"
)
