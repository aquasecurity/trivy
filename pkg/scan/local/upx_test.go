package local_test

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils/upx"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	local "github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

func TestScanner_Scan_UPXDecompressed(t *testing.T) {
	_ = dbtest.InitDB(t, []string{"testdata/fixtures/happy.yaml"})
	defer db.Close()

	binaryPath := "/app/Gemfile.lock"

	railsPkg := ftypes.Package{
		Name:    "rails",
		Version: "4.0.2",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "49be2edc1596dd5d",
			PURL: &packageurl.PackageURL{
				Type:    "gem",
				Name:    "rails",
				Version: "4.0.2",
			},
		},
	}

	c := cache.NewMemoryCache()
	require.NoError(t, c.PutBlob(t.Context(), "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
		SchemaVersion: ftypes.BlobJSONSchemaVersion,
		Size:          1000,
		DiffID:        "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
		OS: ftypes.OS{
			Family: ftypes.Alpine,
			Name:   "3.11",
		},
		Applications: []ftypes.Application{
			{
				Type:     ftypes.Bundler,
				FilePath: binaryPath,
				Packages: []ftypes.Package{railsPkg},
			},
		},
		CustomResources: []ftypes.CustomResource{
			{
				Type:     upx.CustomResourceType,
				FilePath: binaryPath,
			},
		},
	}))

	a := applier.NewApplier(c)
	s := local.NewService(a, ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))

	res, err := s.Scan(t.Context(), "alpine:latest", "", []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"}, types.ScanOptions{
		Scanners: types.Scanners{types.VulnerabilityScanner},
		PkgTypes: []string{
			types.PkgTypeOS,
			types.PkgTypeLibrary,
		},
		PkgRelationships:    ftypes.Relationships,
		VulnSeveritySources: []dbTypes.SourceID{"rubygems"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Results)

	found := false
	for _, r := range res.Results {
		for _, vuln := range r.Vulnerabilities {
			if vuln.VulnerabilityID == "CVE-2014-0081" {
				assert.Contains(t, vuln.Description, "[UPX compressed binary decompressed for scanning]")
				assert.Equal(t, "[UPX compressed binary decompressed for scanning] xss vulnerability", vuln.Description)
				found = true
			}
		}
	}
	assert.True(t, found, "CVE-2014-0081 should be found")
}
