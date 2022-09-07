package cache

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/cloud/report"
)

func (c *Cache) Save(r *report.Report) error {

	existingServices := c.ListAvailableServices(true)

	if err := os.MkdirAll(
		filepath.Dir(c.getMetadataPath()),
		0700,
	); err != nil { // only the current user is allowed to see this report
		return err
	}

	var retainedServices []string
	for _, existing := range existingServices {
		var found bool
		for _, service := range r.ServicesInScope {
			if service == existing {
				found = true
				break
			}
		}
		if found {
			continue
		}
		retainedServices = append(retainedServices, existing)
	}

	for _, service := range r.ServicesInScope {
		serviceFile := c.getServicePath(service)
		if err := os.MkdirAll(
			filepath.Dir(serviceFile),
			0700,
		); err != nil {
			return err
		}
		resultSet, err := r.GetResultsForService(service)
		if err != nil {
			return err
		}
		s, err := os.Create(serviceFile)
		if err != nil {
			return err
		}
		record := Record{
			SchemaVersion: SchemaVersion,
			Service:       service,
			Results:       resultSet.Results,
			CreationTime:  resultSet.CreationTime,
		}
		if err := json.NewEncoder(s).Encode(record); err != nil {
			return err
		}
		_ = s.Close()
	}

	metadataFile := c.getMetadataPath()
	metadata := Metadata{
		SchemaVersion:   SchemaVersion,
		Provider:        c.provider,
		AccountID:       c.accountID,
		Region:          c.region,
		ServicesInScope: append(r.ServicesInScope, retainedServices...),
	}
	m, err := os.Create(metadataFile)
	defer func() { _ = m.Close() }()
	if err != nil {
		return err
	}
	return json.NewEncoder(m).Encode(metadata)
}
