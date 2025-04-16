package secret

var builtinAllowRules = []AllowRule{
	{
		// `.dist-info` dir contains only metadata files such as version, license, and entry points.
		// cf. https://github.com/aquasecurity/trivy/issues/8212
		ID:          "dist-info",
		Description: "Ignore Python .dist-info metadata directories",
		Path:        MustCompile(`\.dist-info\/`),
	},
	{
		ID:          "tests",
		Description: "Avoid test files and paths",
		Path:        MustCompile(`(^(?i)test|\/test|-test|_test|\.test)`),
	},
	{
		ID:          "examples",
		Description: "Avoid example files and paths", // e.g. https://github.com/boto/botocore/blob/develop/botocore/data/organizations/2016-11-28/examples-1.json
		Path:        MustCompile(`example`),
		Regex:       MustCompile("(?i)example"),
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
