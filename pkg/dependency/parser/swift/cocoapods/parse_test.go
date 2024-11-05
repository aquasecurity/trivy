package cocoapods_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/swift/cocoapods"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string // Test input file
		wantPkgs  []ftypes.Package
		wantDeps  []ftypes.Dependency
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			wantPkgs: []ftypes.Package{
				{
					ID:      "AppCenter@4.2.0",
					Name:    "AppCenter",
					Version: "4.2.0",
				},
				{
					ID:      "AppCenter/Analytics@4.2.0",
					Name:    "AppCenter/Analytics",
					Version: "4.2.0",
				},
				{
					ID:      "AppCenter/Core@4.2.0",
					Name:    "AppCenter/Core",
					Version: "4.2.0",
				},
				{
					ID:      "AppCenter/Crashes@4.2.0",
					Name:    "AppCenter/Crashes",
					Version: "4.2.0",
				},
				{
					ID:      "KeychainAccess@4.2.1",
					Name:    "KeychainAccess",
					Version: "4.2.1",
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "AppCenter/Analytics@4.2.0",
					DependsOn: []string{
						"AppCenter/Core@4.2.0",
					},
				},
				{
					ID: "AppCenter/Crashes@4.2.0",
					DependsOn: []string{
						"AppCenter/Core@4.2.0",
					},
				},
				{
					ID: "AppCenter@4.2.0",
					DependsOn: []string{
						"AppCenter/Analytics@4.2.0",
						"AppCenter/Crashes@4.2.0",
					},
				},
			},
		},
		{
			name:      "happy path. lock file without dependencies",
			inputFile: "testdata/empty.lock",
		},
		{
			name:      "sad path. wrong dep format",
			inputFile: "testdata/sad.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, gotDeps, err := cocoapods.NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
