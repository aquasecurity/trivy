package mod

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

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
			ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20211224170007-df43bca6b6ff",
			Name:         "github.com/aquasecurity/go-dep-parser",
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
			Version:      "0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "3.0.0-20210107192922-496545a6307b",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/go-yaml/yaml",
				},
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
			Version:      "0.0.0-20220406074731-71021a481237",
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
			Version:      "0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
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
			Version:      "0.0.0-20211110174639-8257534ffed3",
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
			Version:      "0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
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
			Version:      "0.0.0-20220406074731-71021a481237",
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
			Version:      "0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
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
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
			Version:      "0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "3.0.0-20210107192922-496545a6307b",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefVCS,
					URL:  "https://github.com/go-yaml/yaml",
				},
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
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
			Version:      "3.0.0-20210107192922-496545a6307b",
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
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
			Version:      "3.0.0-20210107192922-496545a6307b",
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
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
			Version:      "0.0.0-20200804184101-5ec99f83aff1",
			Relationship: ftypes.RelationshipIndirect,
		},
		{
			ID:           "gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
			Name:         "gopkg.in/yaml.v3",
			Version:      "3.0.0-20210107192922-496545a6307b",
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
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
			Version:      "0.0.0-20211224170007-df43bca6b6ff",
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
