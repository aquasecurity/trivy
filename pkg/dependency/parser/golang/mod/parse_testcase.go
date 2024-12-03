package mod

import (
	"slices"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	// execute go mod tidy in normal folder
	GoModNormal = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
			Name:         "github.com/aquasecurity/go-version",
			Version:      "v0.0.0-20240603093900-cf8a8d29271d",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-version",
				},
			},
		},
		{
			ID:           "stdlib@v1.22.5",
			Name:         "stdlib",
			Version:      "v1.22.5",
			Relationship: ftypes.RelationshipDirect,
		},
		{
			ID:           "github.com/davecgh/go-spew@v1.1.2-0.20180830191138-d8f796af33cc",
			Name:         "github.com/davecgh/go-spew",
			Version:      "v1.1.2-0.20180830191138-d8f796af33cc",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/davecgh/go-spew",
				},
			},
		},
		{
			ID:           "github.com/pmezard/go-difflib@v1.0.1-0.20181226105442-5d4384ee4fb2",
			Name:         "github.com/pmezard/go-difflib",
			Version:      "v1.0.1-0.20181226105442-5d4384ee4fb2",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/pmezard/go-difflib",
				},
			},
		},
		{
			ID:           "github.com/stretchr/testify@v1.9.0",
			Name:         "github.com/stretchr/testify",
			Version:      "v1.9.0",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/stretchr/testify",
				},
			},
		},
		{
			ID:           "golang.org/x/xerrors@v0.0.0-20231012003039-104605ab7028",
			Name:         "golang.org/x/xerrors",
			Version:      "v0.0.0-20231012003039-104605ab7028",
			Relationship: ftypes.RelationshipIndirect,
		},
	}

	GoModNormalDeps = ftypes.Dependencies{
		{
			ID: "github.com/org/repo",
			DependsOn: []string{
				"github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
				"stdlib@v1.22.5",
			},
		},
	}

	GoModNormalWithoutStdlib = slices.DeleteFunc(slices.Clone(GoModNormal), func(f ftypes.Package) bool {
		return f.Name == "stdlib"
	})

	GoModNormalWithoutStdlibDeps = ftypes.Dependencies{
		{
			ID: "github.com/org/repo",
			DependsOn: []string{
				"github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
			},
		},
	}

	// execute go mod tidy in replaced folder
	GoModReplaced = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20220406074731-71021a481237",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			Name:         "golang.org/x/xerrors",
			Version:      "v0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
	}
	GoModReplacedDeps = ftypes.Dependencies{
		{
			ID: "github.com/org/repo",
			DependsOn: []string{
				"github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
			},
		},
	}

	// execute go mod tidy in replaced folder
	GoModUnreplaced = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211110174639-8257534ffed3",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211110174639-8257534ffed3",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			Name:         "golang.org/x/xerrors",
			Version:      "v0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
	}

	GoModUnreplacedDeps = ftypes.Dependencies{
		{
			ID: "github.com/org/repo",
			DependsOn: []string{
				"github.com/aquasecurity/go-dep-parser@v0.0.0-20211110174639-8257534ffed3",
			},
		},
	}

	// execute go mod tidy in replaced-with-version folder
	GoModReplacedWithVersion = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20220406074731-71021a481237",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			Name:         "golang.org/x/xerrors",
			Version:      "v0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
	}

	GoModReplacedWithVersionDeps = ftypes.Dependencies{
		{
			ID: "github.com/org/repo",
			DependsOn: []string{
				"github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
			},
		},
	}

	// execute go mod tidy in replaced-with-version-mismatch folder
	GoModReplacedWithVersionMismatch = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211224170007-df43bca6b6ff",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			Name:         "golang.org/x/xerrors",
			Version:      "v0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "v3.0.0-20210107192922-496545a6307b",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/go-yaml/yaml",
				},
			},
		},
	}

	defaultGoDepParserDeps = ftypes.Dependencies{
		{
			ID: "github.com/org/repo",
			DependsOn: []string{
				"github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			},
		},
	}

	// execute go mod tidy in replaced-with-local-path folder
	GoModReplacedWithLocalPath = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211224170007-df43bca6b6ff",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "v3.0.0-20210107192922-496545a6307b",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/go-yaml/yaml",
				},
			},
		},
	}

	// execute go mod tidy in replaced-with-local-path-and-version folder
	GoModReplacedWithLocalPathAndVersion = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211224170007-df43bca6b6ff",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "v3.0.0-20210107192922-496545a6307b",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/go-yaml/yaml",
				},
			},
		},
	}

	// execute go mod tidy in replaced-with-local-path-and-version-mismatch folder
	GoModReplacedWithLocalPathAndVersionMismatch = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211224170007-df43bca6b6ff",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
		{
			ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			Name:         "golang.org/x/xerrors",
			Version:      "v0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "v3.0.0-20210107192922-496545a6307b",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/go-yaml/yaml",
				},
			},
		},
	}

	// execute go mod tidy in go116 folder
	GoMod116 = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211224170007-df43bca6b6ff",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
	}

	// execute go mod tidy in no-go-version folder
	GoModNoGoVersion = []ftypes.Package{
		{
			ID:           "github.com/org/repo",
			Name:         "github.com/org/repo",
			Relationship: ftypes.RelationshipRoot,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/org/repo",
				},
			},
		},
		{
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "v0.0.0-20211224170007-df43bca6b6ff",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/aquasecurity/go-dep-parser",
				},
			},
		},
	}
)
