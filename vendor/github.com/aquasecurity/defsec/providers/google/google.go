package google

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/bigquery"
	"github.com/aquasecurity/defsec/providers/google/compute"
	"github.com/aquasecurity/defsec/providers/google/dns"
	"github.com/aquasecurity/defsec/providers/google/gke"
	"github.com/aquasecurity/defsec/providers/google/iam"
	"github.com/aquasecurity/defsec/providers/google/kms"
	"github.com/aquasecurity/defsec/providers/google/sql"
	"github.com/aquasecurity/defsec/providers/google/storage"
)

type Google struct {
	types.Metadata
	BigQuery bigquery.BigQuery
	Compute  compute.Compute
	DNS      dns.DNS
	GKE      gke.GKE
	KMS      kms.KMS
	IAM      iam.IAM
	SQL      sql.SQL
	Storage  storage.Storage
}
