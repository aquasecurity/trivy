package secret

var builtinAllowRules = []AllowRule{
	{
		ID:          "tests",
		Description: "Avoid test files and paths",
		Path:        MustCompile(`(^test|\/test|-test|_test|\.test)`),
	},
	{
		ID:          "examples",
		Description: "Avoid example files and paths", // e.g. https://github.com/boto/botocore/blob/develop/botocore/data/organizations/2016-11-28/examples-1.json
		Path:        MustCompile(`example`),
	},
	{
		ID:          "vendor",
		Description: "Vendor dirs",
		Path:        MustCompile(`\/vendor\/`),
	},
	{
		ID:          "usr-dirs",
		Description: "System dirs",
		Path:        MustCompile(`^usr\/(?:share|include|lib)\/`),
	},
	{
		ID:          "locale-dir",
		Description: "Locales directory contains locales file",
		Path:        MustCompile(`\/locales?\/`),
	},
	{
		ID:          "markdown",
		Description: "Markdown files",
		Path:        MustCompile(`\.md$`),
	},
	{
		ID:          "node.js",
		Description: "Node container images",
		Path:        MustCompile(`^opt\/yarn-v[\d.]+\/`),
	},
	{
		ID:          "golang",
		Description: "Go container images",
		Path:        MustCompile(`^usr\/local\/go\/`),
	},
	{
		ID:          "python",
		Description: "Python container images",
		Path:        MustCompile(`^usr\/local\/lib\/python[\d.]+\/`),
	},
	{
		ID:          "rubygems",
		Description: "Ruby container images",
		Path:        MustCompile(`^usr\/lib\/gems\/`),
	},
	{
		ID:          "wordpress",
		Description: "Wordpress container images",
		Path:        MustCompile(`^usr\/src\/wordpress\/`),
	},
	{
		ID:          "anaconda-log",
		Description: "Anaconda CI Logs in container images",
		Path:        MustCompile(`^var\/log\/anaconda\/`),
	},
}
