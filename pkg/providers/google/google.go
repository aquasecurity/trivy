package google

import (
	"github.com/aquasecurity/trivy/pkg/providers/google/bigquery"
	"github.com/aquasecurity/trivy/pkg/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/providers/google/dns"
	"github.com/aquasecurity/trivy/pkg/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/providers/google/kms"
	"github.com/aquasecurity/trivy/pkg/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/providers/google/storage"
)

type Google struct {
	BigQuery bigquery.BigQuery
	Compute  compute.Compute
	DNS      dns.DNS
	GKE      gke.GKE
	KMS      kms.KMS
	IAM      iam.IAM
	SQL      sql.SQL
	Storage  storage.Storage
}
