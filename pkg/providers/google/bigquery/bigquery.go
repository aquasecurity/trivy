package bigquery

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type BigQuery struct {
	Datasets []Dataset
}

type Dataset struct {
	Metadata     defsecTypes.MisconfigMetadata
	ID           defsecTypes.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	Metadata     defsecTypes.MisconfigMetadata
	Role         defsecTypes.StringValue
	Domain       defsecTypes.StringValue
	SpecialGroup defsecTypes.StringValue
}
