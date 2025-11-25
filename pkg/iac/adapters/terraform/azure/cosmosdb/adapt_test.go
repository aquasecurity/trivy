package cosmosdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/cosmosdb"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptCosmosDBAccount(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cosmosdb.Account
	}{
		{
			name: "default values",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
}
`,
			expected: cosmosdb.Account{
				Metadata:      iacTypes.NewTestMetadata(),
				IPRangeFilter: []iacTypes.StringValue{},
			},
		},
		{
			name: "with ip_range_filter single value",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	ip_range_filter = ["10.0.0.0/16"]
}
`,
			expected: cosmosdb.Account{
				Metadata: iacTypes.NewTestMetadata(),
				IPRangeFilter: []iacTypes.StringValue{
					iacTypes.StringTest("10.0.0.0/16"),
				},
			},
		},
		{
			name: "with ip_range_filter multiple values",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	ip_range_filter = ["10.0.0.0/16", "192.168.1.0/24", "172.16.0.0/12"]
}
`,
			expected: cosmosdb.Account{
				Metadata: iacTypes.NewTestMetadata(),
				IPRangeFilter: []iacTypes.StringValue{
					iacTypes.StringTest("10.0.0.0/16"),
					iacTypes.StringTest("192.168.1.0/24"),
					iacTypes.StringTest("172.16.0.0/12"),
				},
			},
		},
		{
			name: "with ip_range_filter multiple values",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	ip_range_filter = ["10.0.0.0/8", "172.16.0.0/12"]
}
`,
			expected: cosmosdb.Account{
				Metadata: iacTypes.NewTestMetadata(),
				IPRangeFilter: []iacTypes.StringValue{
					iacTypes.StringTest("10.0.0.0/8"),
					iacTypes.StringTest("172.16.0.0/12"),
				},
			},
		},
		{
			name: "empty ip_range_filter",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	ip_range_filter = []
}
`,
			expected: cosmosdb.Account{
				Metadata:      iacTypes.NewTestMetadata(),
				IPRangeFilter: nil, // AsStringValues() returns nil for empty lists
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCosmosDBAccount(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCosmosDBAccounts(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []cosmosdb.Account
	}{
		{
			name: "single account",
			terraform: `
resource "azurerm_cosmosdb_account" "example1" {
}
`,
			expected: []cosmosdb.Account{
				{
					Metadata:      iacTypes.NewTestMetadata(),
					IPRangeFilter: []iacTypes.StringValue{},
				},
			},
		},
		{
			name: "multiple accounts",
			terraform: `
resource "azurerm_cosmosdb_account" "example1" {
	ip_range_filter = ["10.0.0.0/16"]
}

resource "azurerm_cosmosdb_account" "example2" {
	ip_range_filter = ["192.168.0.0/16"]
}
`,
			expected: []cosmosdb.Account{
				{
					Metadata: iacTypes.NewTestMetadata(),
					IPRangeFilter: []iacTypes.StringValue{
						iacTypes.StringTest("10.0.0.0/16"),
					},
				},
				{
					Metadata: iacTypes.NewTestMetadata(),
					IPRangeFilter: []iacTypes.StringValue{
						iacTypes.StringTest("192.168.0.0/16"),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCosmosDBAccounts(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cosmosdb.CosmosDB
	}{
		{
			name: "basic",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	ip_range_filter = ["10.0.0.0/16"]
}
`,
			expected: cosmosdb.CosmosDB{
				Accounts: []cosmosdb.Account{
					{
						Metadata: iacTypes.NewTestMetadata(),
						IPRangeFilter: []iacTypes.StringValue{
							iacTypes.StringTest("10.0.0.0/16"),
						},
					},
				},
			},
		},
		{
			name: "multiple accounts",
			terraform: `
resource "azurerm_cosmosdb_account" "example1" {
}

resource "azurerm_cosmosdb_account" "example2" {
	ip_range_filter = ["192.168.0.0/16"]
}
`,
			expected: cosmosdb.CosmosDB{
				Accounts: []cosmosdb.Account{
					{
						Metadata:      iacTypes.NewTestMetadata(),
						IPRangeFilter: []iacTypes.StringValue{},
					},
					{
						Metadata: iacTypes.NewTestMetadata(),
						IPRangeFilter: []iacTypes.StringValue{
							iacTypes.StringTest("192.168.0.0/16"),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
resource "azurerm_cosmosdb_account" "example" {
	ip_range_filter = ["10.0.0.0/16", "192.168.1.0/24"]
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Accounts, 1)

	account := adapted.Accounts[0]

	assert.Equal(t, 2, account.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, account.Metadata.Range().GetEndLine())

	require.Len(t, account.IPRangeFilter, 2)
	assert.Equal(t, 3, account.IPRangeFilter[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, account.IPRangeFilter[0].GetMetadata().Range().GetEndLine())
	assert.Equal(t, 3, account.IPRangeFilter[1].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, account.IPRangeFilter[1].GetMetadata().Range().GetEndLine())
}
