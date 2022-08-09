package cache

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
)

const SchemaVersion = 1

type Metadata struct {
	SchemaVersion   int      `json:"schema_version"`
	Provider        string   `json:"provider"`
	AccountID       string   `json:"account_id"`
	Region          string   `json:"region"`
	ServicesInScope []string `json:"services"`
}

type Record struct {
	SchemaVersion int           `json:"schema_version"`
	Service       string        `json:"service"`
	Results       types.Results `json:"results"`
	CreationTime  time.Time     `json:"creation_time"`
}
