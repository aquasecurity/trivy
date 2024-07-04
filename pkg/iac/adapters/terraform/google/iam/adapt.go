package iam

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) iam.IAM {
	return (&adapter{
		orgs:         make(map[string]*iam.Organization),
		projects:     make(map[string]*iam.Project),
		projectsByID: make(map[string]string), // projectID -> blockID
		folders:      make(map[string]*iam.Folder),
		modules:      modules,
	}).Adapt()
}

type adapter struct {
	modules                       terraform.Modules
	orgs                          map[string]*iam.Organization
	folders                       map[string]*iam.Folder
	projects                      map[string]*iam.Project
	projectsByID                  map[string]string
	workloadIdentityPoolProviders []iam.WorkloadIdentityPoolProvider
}

func (a *adapter) Adapt() iam.IAM {
	a.adaptOrganizationIAM()
	a.adaptFolderIAM()
	a.adaptProjectIAM()
	a.adaptWorkloadIdentityPoolProviders()
	return a.buildIAMOutput()
}

func (a *adapter) buildIAMOutput() iam.IAM {
	return iam.IAM{
		Organizations:                 fromPtrSlice(lo.Values(a.orgs)),
		Folders:                       fromPtrSlice(lo.Values(a.folders)),
		Projects:                      fromPtrSlice(lo.Values(a.projects)),
		WorkloadIdentityPoolProviders: a.workloadIdentityPoolProviders,
	}
}

func fromPtrSlice[T any](collection []*T) []T {
	if len(collection) == 0 {
		return nil
	}

	result := make([]T, 0, len(collection))
	for _, item := range collection {
		if item == nil {
			continue
		}
		result = append(result, *item)
	}
	return result
}
