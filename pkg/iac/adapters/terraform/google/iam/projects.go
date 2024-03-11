package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
)

type parentedProject struct {
	blockID       string
	orgBlockID    string
	folderBlockID string
	id            string
	orgID         string
	folderID      string
	project       iam.Project
}

func (a *adapter) adaptProjects() {
	for _, projectBlock := range a.modules.GetResourcesByType(GoogleProject) {
		var project parentedProject
		project.project.Metadata = projectBlock.GetMetadata()
		idAttr := projectBlock.GetAttribute("project_id")
		if !idAttr.IsString() {
			continue
		}
		project.id = idAttr.Value().AsString()

		project.blockID = projectBlock.ID()

		orgAttr := projectBlock.GetAttribute("org_id")
		if orgAttr.IsString() {
			project.orgID = orgAttr.Value().AsString()
		}
		folderAttr := projectBlock.GetAttribute("folder_id")
		if folderAttr.IsString() {
			project.folderID = folderAttr.Value().AsString()
		}

		autoCreateNetworkAttr := projectBlock.GetAttribute("auto_create_network")
		project.project.AutoCreateNetwork = autoCreateNetworkAttr.AsBoolValueOrDefault(true, projectBlock)

		if orgAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(orgAttr, projectBlock); err == nil {
				if referencedBlock.TypeLabel() == GoogleOrganization {
					project.orgBlockID = referencedBlock.ID()
					a.addOrg(project.orgBlockID)
				}
			}
		}
		if folderAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(folderAttr, projectBlock); err == nil {
				if referencedBlock.TypeLabel() == GoogleFolder {
					project.folderBlockID = referencedBlock.ID()
				}
			}
		}
		a.projects = append(a.projects, project)
	}
}
