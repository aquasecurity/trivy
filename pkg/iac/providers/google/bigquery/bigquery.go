package bigquery

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type BigQuery struct {
	Datasets []Dataset
}

type Dataset struct {
	Metadata     defsecTypes.Metadata
	ID           defsecTypes.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	Metadata     defsecTypes.Metadata
	Role         defsecTypes.StringValue
	Domain       defsecTypes.StringValue
	SpecialGroup defsecTypes.StringValue
}
