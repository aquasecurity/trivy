package iam

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam

const GoogleProject = "google_project"

func (a *adapter) adaptProjectIAM() {
	a.adaptProjectMembers()
	a.adaptProjectBindings()
}

func (a *adapter) adaptMember(iamBlock *terraform.Block) iam.Member {
	return AdaptMember(iamBlock, a.modules)
}

func AdaptMember(iamBlock *terraform.Block, modules terraform.Modules) iam.Member {
	member := iam.Member{
		Metadata:              iamBlock.GetMetadata(),
		Member:                iamBlock.GetAttribute("member").AsStringValueOrDefault("", iamBlock),
		Role:                  iamBlock.GetAttribute("role").AsStringValueOrDefault("", iamBlock),
		DefaultServiceAccount: iacTypes.BoolDefault(false, iamBlock.GetMetadata()),
	}

	memberAttr := iamBlock.GetAttribute("member")
	if referencedBlock, err := modules.GetReferencedBlock(memberAttr, iamBlock); err == nil {
		if strings.HasSuffix(referencedBlock.TypeLabel(), "_default_service_account") {
			member.DefaultServiceAccount = iacTypes.Bool(true, memberAttr.GetMetadata())
		}
	}

	return member
}

var projectMemberResources = []string{
	"google_project_iam_member",
	"google_cloud_run_service_iam_member",
	"google_compute_instance_iam_member",
	"google_compute_subnetwork_iam_member",
	"google_data_catalog_entry_group_iam_member",
	"google_folder_iam_member",
	"google_pubsub_subscription_iam_member",
	"google_pubsub_topic_iam_member",
	"google_sourcerepo_repository_iam_member",
	"google_spanner_database_iam_member",
	"google_spanner_instance_iam_member",
	"google_storage_bucket_iam_member",
}

func (a *adapter) adaptProjectMembers() {

	for _, memberType := range projectMemberResources {
		for _, iamBlock := range a.modules.GetResourcesByType(memberType) {
			member := a.adaptMember(iamBlock)
			projectAttr := iamBlock.GetAttribute("project")
			if projectAttr.IsString() {
				var foundProject bool
				projectID := projectAttr.Value().AsString()
				for i, project := range a.projects {
					if project.id == projectID {
						project.project.Members = append(project.project.Members, member)
						a.projects[i] = project
						foundProject = true
						break
					}
				}
				if foundProject {
					continue
				}
			}

			if refBlock, err := a.modules.GetReferencedBlock(projectAttr, iamBlock); err == nil {
				if refBlock.TypeLabel() == GoogleProject {
					var foundProject bool
					for i, project := range a.projects {
						if project.blockID == refBlock.ID() {
							project.project.Members = append(project.project.Members, member)
							a.projects[i] = project
							foundProject = true
							break
						}
					}
					if foundProject {
						continue
					}

				}
			}

			// we didn't find the project - add an unmanaged one
			// unless it already belongs to an existing folder
			var foundFolder bool
			if refBlock, err := a.modules.GetReferencedBlock(iamBlock.GetAttribute("folder"), iamBlock); err == nil {
				for _, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						foundFolder = true
					}
				}
			}
			if foundFolder {
				continue
			}

			a.projects = append(a.projects, parentedProject{
				project: iam.Project{
					Metadata:          iacTypes.NewUnmanagedMetadata(),
					AutoCreateNetwork: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
					Members:           []iam.Member{member},
					Bindings:          nil,
				},
			})
		}
	}
}

func (a *adapter) adaptBinding(iamBlock *terraform.Block) iam.Binding {
	return AdaptBinding(iamBlock, a.modules)
}

func AdaptBinding(iamBlock *terraform.Block, modules terraform.Modules) iam.Binding {
	binding := iam.Binding{
		Metadata:                      iamBlock.GetMetadata(),
		Members:                       nil,
		Role:                          iamBlock.GetAttribute("role").AsStringValueOrDefault("", iamBlock),
		IncludesDefaultServiceAccount: iacTypes.BoolDefault(false, iamBlock.GetMetadata()),
	}
	membersAttr := iamBlock.GetAttribute("members")
	members := membersAttr.AsStringValues().AsStrings()
	for _, member := range members {
		binding.Members = append(binding.Members, iacTypes.String(member, membersAttr.GetMetadata()))
	}
	if referencedBlock, err := modules.GetReferencedBlock(membersAttr, iamBlock); err == nil {
		if strings.HasSuffix(referencedBlock.TypeLabel(), "_default_service_account") {
			binding.IncludesDefaultServiceAccount = iacTypes.Bool(true, membersAttr.GetMetadata())
		}
	}
	return binding
}

var projectBindingResources = []string{
	"google_project_iam_binding",
	"google_cloud_run_service_iam_binding",
	"google_compute_instance_iam_binding",
	"google_compute_subnetwork_iam_binding",
	"google_data_catalog_entry_group_iam_binding",
	"google_folder_iam_binding",
	"google_pubsub_subscription_iam_binding",
	"google_pubsub_topic_iam_binding",
	"google_sourcerepo_repository_iam_binding",
	"google_spanner_database_iam_binding",
	"google_spanner_instance_iam_binding",
	"google_storage_bucket_iam_binding",
}

func (a *adapter) adaptProjectDataBindings() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_project_iam_policy") {

		policyAttr := iamBlock.GetAttribute("policy_data")
		if policyAttr.IsNil() {
			continue
		}
		policyBlock, err := a.modules.GetReferencedBlock(policyAttr, iamBlock)
		if err != nil {
			continue
		}
		bindings := ParsePolicyBlock(policyBlock)
		projectAttr := iamBlock.GetAttribute("project")
		if projectAttr.IsString() {
			var foundProject bool
			projectID := projectAttr.Value().AsString()
			for i, project := range a.projects {
				if project.id == projectID {
					project.project.Bindings = append(project.project.Bindings, bindings...)
					a.projects[i] = project
					foundProject = true
					break
				}
			}
			if foundProject {
				continue
			}
		}

		if refBlock, err := a.modules.GetReferencedBlock(projectAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleProject {
				var foundProject bool
				for i, project := range a.projects {
					if project.blockID == refBlock.ID() {
						project.project.Bindings = append(project.project.Bindings, bindings...)
						a.projects[i] = project
						foundProject = true
						break
					}
				}
				if foundProject {
					continue
				}

			}
		}

		// we didn't find the project - add an unmanaged one
		a.projects = append(a.projects, parentedProject{
			project: iam.Project{
				Metadata:          iacTypes.NewUnmanagedMetadata(),
				AutoCreateNetwork: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				Members:           nil,
				Bindings:          bindings,
			},
		})
	}

}

func (a *adapter) adaptProjectBindings() {

	a.adaptProjectDataBindings()

	for _, bindingType := range projectBindingResources {
		for _, iamBlock := range a.modules.GetResourcesByType(bindingType) {
			binding := a.adaptBinding(iamBlock)
			projectAttr := iamBlock.GetAttribute("project")
			if projectAttr.IsString() {
				var foundProject bool
				projectID := projectAttr.Value().AsString()
				for i, project := range a.projects {
					if project.id == projectID {
						project.project.Bindings = append(project.project.Bindings, binding)
						a.projects[i] = project
						foundProject = true
						break
					}
				}
				if foundProject {
					continue
				}
			}

			if refBlock, err := a.modules.GetReferencedBlock(projectAttr, iamBlock); err == nil {
				if refBlock.TypeLabel() == GoogleProject {
					var foundProject bool
					for i, project := range a.projects {
						if project.blockID == refBlock.ID() {
							project.project.Bindings = append(project.project.Bindings, binding)
							a.projects[i] = project
							foundProject = true
							break
						}
					}
					if foundProject {
						continue
					}

				}
			}

			// we didn't find the project - add an unmanaged one
			// unless it already belongs to an existing folder
			var foundFolder bool
			if refBlock, err := a.modules.GetReferencedBlock(iamBlock.GetAttribute("folder"), iamBlock); err == nil {
				for _, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						foundFolder = true
					}
				}
			}
			if foundFolder {
				continue
			}
			a.projects = append(a.projects, parentedProject{
				project: iam.Project{
					Metadata:          iacTypes.NewUnmanagedMetadata(),
					AutoCreateNetwork: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
					Members:           nil,
					Bindings:          []iam.Binding{binding},
				},
			})
		}
	}
}
