package mod

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// execute go mod tidy in normal folder
	GoModNormal = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1", Indirect: true},
		{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20210107192922-496545a6307b", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/go-yaml/yaml"}}},
	}

	// execute go mod tidy in replaced folder
	GoModReplaced = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20220406074731-71021a481237", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1", Indirect: true},
	}

	// execute go mod tidy in replaced-with-version folder
	GoModReplacedWithVersion = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20220406074731-71021a481237", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1", Indirect: true},
	}

	// execute go mod tidy in replaced-with-version-mismatch folder
	GoModReplacedWithVersionMismatch = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1", Indirect: true},
		{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20210107192922-496545a6307b", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/go-yaml/yaml"}}},
	}

	// execute go mod tidy in replaced-with-local-path folder
	GoModReplacedWithLocalPath = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20210107192922-496545a6307b", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/go-yaml/yaml"}}},
	}

	// execute go mod tidy in replaced-with-local-path-and-version folder
	GoModReplacedWithLocalPathAndVersion = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20210107192922-496545a6307b", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/go-yaml/yaml"}}},
	}

	// execute go mod tidy in replaced-with-local-path-and-version-mismatch folder
	GoModReplacedWithLocalPathAndVersionMismatch = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
		{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1", Indirect: true},
		{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20210107192922-496545a6307b", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/go-yaml/yaml"}}},
	}

	// execute go mod tidy in go116 folder
	GoMod116 = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
	}

	// execute go mod tidy in no-go-version folder
	GoModNoGoVersion = []types.Library{
		{Name: "github.com/aquasecurity/go-dep-parser", Version: "0.0.0-20211224170007-df43bca6b6ff", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefVCS, URL: "https://github.com/aquasecurity/go-dep-parser"}}},
	}
)
