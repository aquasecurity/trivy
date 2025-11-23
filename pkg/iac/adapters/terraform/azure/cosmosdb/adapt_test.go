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
				Tags:          iacTypes.MapDefault(make(map[string]string), iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "with tags",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	tags = {
		Environment = "Production"
		Owner       = "DevOps"
	}
}
`,
			expected: cosmosdb.Account{
				Metadata:      iacTypes.NewTestMetadata(),
				IPRangeFilter: []iacTypes.StringValue{},
				Tags: iacTypes.Map(map[string]string{
					"Environment": "Production",
					"Owner":       "DevOps",
				}, iacTypes.NewTestMetadata()),
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
				Tags: iacTypes.MapDefault(make(map[string]string), iacTypes.NewTestMetadata()),
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
				Tags: iacTypes.MapDefault(make(map[string]string), iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "with tags and ip_range_filter",
			terraform: `
resource "azurerm_cosmosdb_account" "example" {
	tags = {
		Environment = "Development"
		Project     = "MyProject"
	}
	ip_range_filter = ["10.0.0.0/8", "172.16.0.0/12"]
}
`,
			expected: cosmosdb.Account{
				Metadata: iacTypes.NewTestMetadata(),
				IPRangeFilter: []iacTypes.StringValue{
					iacTypes.StringTest("10.0.0.0/8"),
					iacTypes.StringTest("172.16.0.0/12"),
				},
				Tags: iacTypes.Map(map[string]string{
					"Environment": "Development",
					"Project":     "MyProject",
				}, iacTypes.NewTestMetadata()),
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
				Tags:          iacTypes.MapDefault(make(map[string]string), iacTypes.NewTestMetadata()),
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
	tags = {
		Name = "account1"
	}
}
`,
			expected: []cosmosdb.Account{
				{
					Metadata:      iacTypes.NewTestMetadata(),
					IPRangeFilter: []iacTypes.StringValue{},
					Tags: iacTypes.Map(map[string]string{
						"Name": "account1",
					}, iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "multiple accounts",
			terraform: `
resource "azurerm_cosmosdb_account" "example1" {
	tags = {
		Name = "account1"
	}
	ip_range_filter = ["10.0.0.0/16"]
}

resource "azurerm_cosmosdb_account" "example2" {
	tags = {
		Name = "account2"
	}
	ip_range_filter = ["192.168.0.0/16"]
}
`,
			expected: []cosmosdb.Account{
				{
					Metadata: iacTypes.NewTestMetadata(),
					IPRangeFilter: []iacTypes.StringValue{
						iacTypes.StringTest("10.0.0.0/16"),
					},
					Tags: iacTypes.Map(map[string]string{
						"Name": "account1",
					}, iacTypes.NewTestMetadata()),
				},
				{
					Metadata: iacTypes.NewTestMetadata(),
					IPRangeFilter: []iacTypes.StringValue{
						iacTypes.StringTest("192.168.0.0/16"),
					},
					Tags: iacTypes.Map(map[string]string{
						"Name": "account2",
					}, iacTypes.NewTestMetadata()),
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
	tags = {
		Environment = "Production"
	}
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
						Tags: iacTypes.Map(map[string]string{
							"Environment": "Production",
						}, iacTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "multiple accounts",
			terraform: `
resource "azurerm_cosmosdb_account" "example1" {
	tags = {
		Name = "account1"
	}
}

resource "azurerm_cosmosdb_account" "example2" {
	tags = {
		Name = "account2"
	}
	ip_range_filter = ["192.168.0.0/16"]
}
`,
			expected: cosmosdb.CosmosDB{
				Accounts: []cosmosdb.Account{
					{
						Metadata:      iacTypes.NewTestMetadata(),
						IPRangeFilter: []iacTypes.StringValue{},
						Tags: iacTypes.Map(map[string]string{
							"Name": "account1",
						}, iacTypes.NewTestMetadata()),
					},
					{
						Metadata: iacTypes.NewTestMetadata(),
						IPRangeFilter: []iacTypes.StringValue{
							iacTypes.StringTest("192.168.0.0/16"),
						},
						Tags: iacTypes.Map(map[string]string{
							"Name": "account2",
						}, iacTypes.NewTestMetadata()),
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
	tags = {
		Environment = "Production"
		Owner       = "DevOps"
	}
	ip_range_filter = ["10.0.0.0/16", "192.168.1.0/24"]
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Accounts, 1)

	account := adapted.Accounts[0]

	assert.Equal(t, 2, account.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, account.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, account.Tags.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, account.Tags.GetMetadata().Range().GetEndLine())

	require.Len(t, account.IPRangeFilter, 2)
	assert.Equal(t, 7, account.IPRangeFilter[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, account.IPRangeFilter[0].GetMetadata().Range().GetEndLine())
	assert.Equal(t, 7, account.IPRangeFilter[1].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, account.IPRangeFilter[1].GetMetadata().Range().GetEndLine())
}
