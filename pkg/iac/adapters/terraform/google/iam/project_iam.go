package iam

import (
	"strings"

	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam

const GoogleProject = "google_project"

func (a *adapter) adaptProjectIAM() {
	a.adaptProjects()
	a.adaptProjectMembers()
	a.adaptProjectBindings()
}

func (a *adapter) adaptProjects() {
	for _, projectBlock := range a.modules.GetResourcesByType(GoogleProject) {
		idAttr := projectBlock.GetAttribute("project_id")
		if idAttr.IsString() {
			a.projectsByID[idAttr.Value().AsString()] = projectBlock.ID()
		}

		a.projects[projectBlock.ID()] = &iam.Project{
			Metadata:          projectBlock.GetMetadata().Root(),
			AutoCreateNetwork: projectBlock.GetAttribute("auto_create_network").AsBoolValueOrDefault(true, projectBlock),
		}
	}
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

// TODO(nikita): add new resources
var projectMemberResources = []string{
	"google_project_iam_member",
	"google_cloud_run_service_iam_member",
	"google_compute_instance_iam_member",
	"google_compute_subnetwork_iam_member",
	"google_data_catalog_entry_group_iam_member",
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

			if project := a.findProject(iamBlock); project != nil {
				project.Members = append(project.Members, member)
			} else {
				// we didn't find the folder - add an unmanaged one
				a.projects[uuid.NewString()] = &iam.Project{
					Metadata:          iacTypes.NewUnmanagedMetadata(),
					AutoCreateNetwork: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
					Members:           []iam.Member{member},
				}
			}
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

// TODO(nikita): add new resources
var projectBindingResources = []string{
	"google_project_iam_binding",
	"google_cloud_run_service_iam_binding",
	"google_compute_instance_iam_binding",
	"google_compute_subnetwork_iam_binding",
	"google_data_catalog_entry_group_iam_binding",
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

		if project := a.findProject(iamBlock); project != nil {
			project.Bindings = append(project.Bindings, bindings...)
		} else {
			// we didn't find the folder - add an unmanaged one
			a.projects[uuid.NewString()] = &iam.Project{
				Metadata:          iacTypes.NewUnmanagedMetadata(),
				AutoCreateNetwork: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				Bindings:          bindings,
			}
		}
	}

}

func (a *adapter) adaptProjectBindings() {

	a.adaptProjectDataBindings()

	for _, bindingType := range projectBindingResources {
		for _, iamBlock := range a.modules.GetResourcesByType(bindingType) {

			binding := a.adaptBinding(iamBlock)

			if project := a.findProject(iamBlock); project != nil {
				project.Bindings = append(project.Bindings, binding)
			} else {
				// we didn't find the folder - add an unmanaged one
				a.projects[uuid.NewString()] = &iam.Project{
					Metadata:          iacTypes.NewUnmanagedMetadata(),
					AutoCreateNetwork: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
					Bindings:          []iam.Binding{binding},
				}
			}
		}
	}
}

func (a *adapter) resolveProjectBlockID(projectAttr *terraform.Attribute, iamBlock *terraform.Block) string {

	if projectAttr.IsString() {
		projectID := projectAttr.Value().AsString()
		if blockID, exists := a.projectsByID[projectID]; exists {
			return blockID
		}
	}

	refBlock, err := a.modules.GetReferencedBlock(projectAttr, iamBlock)
	if err != nil {
		return ""
	}
	return refBlock.ID()
}

func (a *adapter) findProject(iamBlock *terraform.Block) *iam.Project {
	projectAttr := iamBlock.GetAttribute("project")
	blockID := a.resolveProjectBlockID(projectAttr, iamBlock)
	if blockID == "" {
		return nil
	}

	if project, exists := a.projects[blockID]; exists {
		return project
	}

	return nil
}
