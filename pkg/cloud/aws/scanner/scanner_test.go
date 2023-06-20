package scanner

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	awsScanner "github.com/aquasecurity/defsec/pkg/scanners/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/require"
	"io/fs"
)

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/state"
)

func Test_AWSInputSelectorsWithConfigData(t *testing.T) {
	testCases := []struct {
		name            string
		srcFS           fs.FS
		dataFS          fs.FS
		state           state.State
		expectedResults struct {
			totalResults int
			summaries    []string
		}
	}{
		{
			name: "single cloud, single selector with config data",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0999
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: rds
package builtin.aws.rds.aws0999
import data.settings.DS0999.ignore_deletion_protection
deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	not ignore_deletion_protection
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}
`,
			}),
			dataFS: testutil.CreateFS(t, map[string]string{
				"config-data/data.json": `{
    "settings": {
		"DS0999": {
			"ignore_deletion_protection": false
		}
    }
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 1, summaries: []string{"RDS Publicly Accessible"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := awsScanner.New(
				options.ScannerWithEmbeddedPolicies(false),
				options.ScannerWithPolicyFilesystem(tc.srcFS),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithPolicyDirs("policies/"),
				options.ScannerWithDataFilesystem(tc.dataFS),
				options.ScannerWithDataDirs("config-data/"))

			results, err := scanner.Scan(context.TODO(), &tc.state)
			require.NoError(t, err, tc.name)
			require.Equal(t, tc.expectedResults.totalResults, len(results), tc.name)
			for i := range results.GetFailed() {
				require.Contains(t, tc.expectedResults.summaries, results.GetFailed()[i].Rule().Summary, tc.name)
			}
		})
	}
}
