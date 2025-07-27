package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.IAM
	}{
		{
			name: "basic",
			terraform: `
data "google_organization" "org" {
  domain = "example.com"
}

resource "google_project" "my_project" {
  name                = "My Project"
  project_id          = "your-project-id"
  org_id              = data.google_organization.org.org_id
  auto_create_network = true
}

resource "google_folder" "department1" {
  display_name = "Department 1"
  parent       = data.google_organization.org.org_id
}

resource "google_folder_iam_member" "admin" {
  folder = google_folder.department1.name
  role   = "roles/editor"
  member = "user:alice@gmail.com"
}

resource "google_folder_iam_binding" "folder-123" {
  folder = google_folder.department1.name
  role   = "roles/nothing"
  members = [
    "user:not-alice@gmail.com",
  ]
}

resource "google_organization_iam_member" "org-123" {
  org_id = data.google_organization.org.org_id
  role   = "roles/whatever"
  member = "user:member@gmail.com"
}

resource "google_organization_iam_binding" "binding" {
  org_id = data.google_organization.org.org_id
  role   = "roles/browser"

  members = [
    "user:member_2@gmail.com",
  ]
}

resource "google_iam_workload_identity_pool_provider" "example" {
  workload_identity_pool_id          = "example-pool"
  workload_identity_pool_provider_id = "example-provider"
  attribute_condition                = "assertion.repository_owner=='your-github-organization'"
}
`,
			expected: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          iacTypes.NewTestMetadata(),
						AutoCreateNetwork: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
				},
				Folders: []iam.Folder{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              iacTypes.NewTestMetadata(),
								Member:                iacTypes.String("user:alice@gmail.com", iacTypes.NewTestMetadata()),
								Role:                  iacTypes.String("roles/editor", iacTypes.NewTestMetadata()),
								DefaultServiceAccount: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Members: []iacTypes.StringValue{
									iacTypes.String("user:not-alice@gmail.com", iacTypes.NewTestMetadata()),
								},
								Role:                          iacTypes.String("roles/nothing", iacTypes.NewTestMetadata()),
								IncludesDefaultServiceAccount: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							},
						},
					},
				},
				Organizations: []iam.Organization{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              iacTypes.NewTestMetadata(),
								Member:                iacTypes.String("user:member@gmail.com", iacTypes.NewTestMetadata()),
								Role:                  iacTypes.String("roles/whatever", iacTypes.NewTestMetadata()),
								DefaultServiceAccount: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Members: []iacTypes.StringValue{
									iacTypes.String("user:member_2@gmail.com", iacTypes.NewTestMetadata())},
								Role:                          iacTypes.String("roles/browser", iacTypes.NewTestMetadata()),
								IncludesDefaultServiceAccount: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							},
						},
					},
				},
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata: iacTypes.NewTestMetadata(),

						WorkloadIdentityPoolId:         iacTypes.String("example-pool", iacTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: iacTypes.String("example-provider", iacTypes.NewTestMetadata()),
						AttributeCondition:             iacTypes.String("assertion.repository_owner=='your-github-organization'", iacTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "iam policies",
			terraform: `
resource "google_folder" "test" {
  display_name = "Department 1"
}

resource "google_folder_iam_policy" "folder" {
  folder      = google_folder.test.folder_id
  policy_data = data.google_iam_policy.folder_admin.policy_data
}

data "google_iam_policy" "folder_admin" {
  binding {
    role = "roles/editor"

    members = [
      "user:jane@example.com",
    ]
  }
}

data "google_organization" "test" {
  domain = "example.com"
}

resource "google_organization_iam_policy" "organization" {
  org_id      = data.google_organization.test.name
  policy_data = data.google_iam_policy.org_admin.policy_data
}

data "google_iam_policy" "org_admin" {
  binding {
    role = "roles/editor"

    members = [
      "user:jane2@example.com",
    ]
  }
}

resource "google_project" "test" {
  name = "My Project2"
}

resource "google_project_iam_policy" "project" {
  project     = google_project.test.id
  policy_data = data.google_iam_policy.project_admin.policy_data
}

data "google_iam_policy" "project_admin" {
  binding {
    role = "roles/editor"

    members = [
      "user:jane3@example.com",
    ]
  }
}
`,
			expected: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Role:     iacTypes.StringTest("roles/editor"),
								Members: []iacTypes.StringValue{
									iacTypes.StringTest("user:jane@example.com"),
								},
							},
						},
					},
				},
				Organizations: []iam.Organization{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Role:     iacTypes.StringTest("roles/editor"),
								Members: []iacTypes.StringValue{
									iacTypes.StringTest("user:jane2@example.com"),
								},
							},
						},
					},
				},
				Projects: []iam.Project{
					{
						AutoCreateNetwork: iacTypes.BoolTest(true),
						Metadata:          iacTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Role:     iacTypes.StringTest("roles/editor"),
								Members: []iacTypes.StringValue{
									iacTypes.StringTest("user:jane3@example.com"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "google_project_iam ref by value",
			terraform: `
resource "google_project" "my_project" {
  name       = "My Project"
  project_id = "your-project-id"
  org_id     = "1234567"
}


resource "google_project_iam_member" "project" {
  project = "your-project-id"
  role    = "roles/editor"
  member  = "user:jane@example.com"
}
`,
			expected: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          iacTypes.NewTestMetadata(),
						AutoCreateNetwork: iacTypes.BoolTest(true),
						Members: []iam.Member{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Role:     iacTypes.StringTest("roles/editor"),
								Member:   iacTypes.StringTest("user:jane@example.com"),
							},
						},
					},
				},
			},
		},
		{
			name: "only google_project_iam",
			terraform: `
resource "google_project_iam_member" "project" {
  project = "your-project-id"
  role    = "roles/editor"
  member  = "user:jane@example.com"
}		
`,
			expected: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          iacTypes.NewTestMetadata(),
						AutoCreateNetwork: iacTypes.BoolTest(false),
						Members: []iam.Member{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Role:     iacTypes.StringTest("roles/editor"),
								Member:   iacTypes.StringTest("user:jane@example.com"),
							},
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
		data "google_organization" "org" {
			domain = "example.com"
		}
			
		resource "google_project" "my_project" {
			name       = "My Project"
			project_id = "your-project-id"
			org_id = data.google_organization.org.id
			auto_create_network = true
		}

		resource "google_folder" "department1" {
			display_name = "Department 1"
			parent       = data.google_organization.org.id
		}

		resource "google_folder_iam_binding" "folder-123" {
			folder = google_folder.department1.name
			role    = "roles/nothing"
			members = [
				"user:not-alice@gmail.com",
			]
		}

		resource "google_folder_iam_member" "admin" {
			folder = google_folder.department1.name
			role   = "roles/editor"
			member = "user:alice@gmail.com"
		}

		resource "google_organization_iam_member" "org-123" {
			org_id = data.google_organization.org.id
			role    = "roles/whatever"
			member = "user:member@gmail.com"
		}

		resource "google_organization_iam_binding" "binding" {
			org_id = data.google_organization.org.id
			role    = "roles/browser"
			
			members = [
				"user:member_2@gmail.com",
			]
		}
		
		resource "google_iam_workload_identity_pool_provider" "example" {
			workload_identity_pool_id          = "example-pool"
			workload_identity_pool_provider_id = "example-provider"
			attribute_condition                = "assertion.repository_owner=='your-github-organization'"
		}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Organizations, 1)
	require.Len(t, adapted.Projects, 1)
	require.Len(t, adapted.Folders, 1)
	require.Len(t, adapted.Organizations[0].Bindings, 1)
	require.Len(t, adapted.Organizations[0].Members, 1)
	require.Len(t, adapted.WorkloadIdentityPoolProviders, 1)

	project := adapted.Projects[0]
	folder := adapted.Folders[0]
	binding := adapted.Organizations[0].Bindings[0]
	member := adapted.Organizations[0].Members[0]
	pool := adapted.WorkloadIdentityPoolProviders[0]

	assert.Equal(t, 6, project.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, project.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, project.AutoCreateNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, project.AutoCreateNetwork.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, folder.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, folder.Metadata.Range().GetEndLine())

	assert.Equal(t, 18, folder.Bindings[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 24, folder.Bindings[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 20, folder.Bindings[0].Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, folder.Bindings[0].Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, folder.Bindings[0].Members[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, folder.Bindings[0].Members[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, folder.Members[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 30, folder.Members[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 29, folder.Members[0].Member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 29, folder.Members[0].Member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 28, folder.Members[0].Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, folder.Members[0].Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 32, member.Metadata.Range().GetStartLine())
	assert.Equal(t, 36, member.Metadata.Range().GetEndLine())

	assert.Equal(t, 34, member.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, member.Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 35, member.Member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, member.Member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, binding.Metadata.Range().GetStartLine())
	assert.Equal(t, 45, binding.Metadata.Range().GetEndLine())

	assert.Equal(t, 40, binding.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, binding.Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 42, binding.Members[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 44, binding.Members[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 51, pool.Metadata.Range().GetEndLine())
}

func TestAdaptAuditConfigs(t *testing.T) {
	modules := tftestutil.CreateModulesFromSource(t, `
resource "google_project_iam_audit_config" "project_audit" {
  project = "test-project"
  service = "allServices"
  
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  
  audit_log_config {
    log_type = "DATA_WRITE"
    exempted_members = [
      "user:alice@example.com",
      "serviceAccount:test@project.iam.gserviceaccount.com"
    ]
  }
}

resource "google_organization_iam_audit_config" "org_audit" {
  org_id  = "123456789"
  service = "storage.googleapis.com"
  
  audit_log_config {
    log_type = "DATA_READ"
    exempted_members = ["user:bob@example.com"]
  }
}

resource "google_folder_iam_audit_config" "folder_audit" {
  folder  = "folders/987654321"
  service = "compute.googleapis.com"
  
  audit_log_config {
    log_type = "ADMIN_READ"
  }
}
`, ".tf")

	adapted := Adapt(modules)

	// These will be unmanaged resources since we didn't create base resources
	require.GreaterOrEqual(t, len(adapted.Projects), 1)
	require.GreaterOrEqual(t, len(adapted.Organizations), 1)
	require.GreaterOrEqual(t, len(adapted.Folders), 1)

	// Test project audit config
	project := adapted.Projects[0]
	require.Len(t, project.AuditConfigs, 1)

	projectAudit := project.AuditConfigs[0]
	assert.Equal(t, "allServices", projectAudit.Service.Value())
	require.Len(t, projectAudit.AuditLogConfigs, 2)

	// First audit log config - ADMIN_READ
	adminReadConfig := projectAudit.AuditLogConfigs[0]
	assert.Equal(t, "ADMIN_READ", adminReadConfig.LogType.Value())
	assert.Empty(t, adminReadConfig.ExemptedMembers)

	// Second audit log config - DATA_WRITE with exempted members
	dataWriteConfig := projectAudit.AuditLogConfigs[1]
	assert.Equal(t, "DATA_WRITE", dataWriteConfig.LogType.Value())
	require.Len(t, dataWriteConfig.ExemptedMembers, 2)
	assert.Equal(t, "user:alice@example.com", dataWriteConfig.ExemptedMembers[0].Value())
	assert.Equal(t, "serviceAccount:test@project.iam.gserviceaccount.com", dataWriteConfig.ExemptedMembers[1].Value())

	// Test organization audit config
	org := adapted.Organizations[0]
	require.Len(t, org.AuditConfigs, 1)

	orgAudit := org.AuditConfigs[0]
	assert.Equal(t, "storage.googleapis.com", orgAudit.Service.Value())
	require.Len(t, orgAudit.AuditLogConfigs, 1)

	orgLogConfig := orgAudit.AuditLogConfigs[0]
	assert.Equal(t, "DATA_READ", orgLogConfig.LogType.Value())
	require.Len(t, orgLogConfig.ExemptedMembers, 1)
	assert.Equal(t, "user:bob@example.com", orgLogConfig.ExemptedMembers[0].Value())

	// Test folder audit config
	folder := adapted.Folders[0]
	require.Len(t, folder.AuditConfigs, 1)

	folderAudit := folder.AuditConfigs[0]
	assert.Equal(t, "compute.googleapis.com", folderAudit.Service.Value())
	require.Len(t, folderAudit.AuditLogConfigs, 1)

	folderLogConfig := folderAudit.AuditLogConfigs[0]
	assert.Equal(t, "ADMIN_READ", folderLogConfig.LogType.Value())
	assert.Empty(t, folderLogConfig.ExemptedMembers)
}
