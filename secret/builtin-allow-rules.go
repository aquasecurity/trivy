package secret

var builtinAllowRules = []AllowRule{
	{
		ID:          "tests",
		Description: "Avoid paths containing test",
		Path:        MustCompile(`\/test`),
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
		Path:        MustCompile(`\/locale\/`),
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
