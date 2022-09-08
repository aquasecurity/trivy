package cache

import (
	"encoding/json"
	"os"

	"github.com/aquasecurity/trivy/pkg/cloud/report"
)

func (c *Cache) loadMetadata() (*Metadata, error) {
	metadataFile := c.getMetadataPath()
	m, err := os.Open(metadataFile)
	if err != nil {
		return nil, ErrCacheNotFound
	}
	defer func() { _ = m.Close() }()

	var metadata Metadata
	if err := json.NewDecoder(m).Decode(&metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (c *Cache) LoadReport(services ...string) (*report.Report, error) {

	metadata, err := c.loadMetadata()
	if err != nil {
		return nil, err
	}

	base := report.New(c.provider, c.accountID, c.region, nil, nil)

	for _, service := range services {
		if !contains(metadata.ServicesInScope, service) {
			continue
		}
		if r, err := c.loadService(service, base); err != nil {
			return r, err
		}
	}

	return base, nil
}

func (c *Cache) loadService(service string, base *report.Report) (*report.Report, error) {
	serviceFile := c.getServicePath(service)
	s, err := os.Open(serviceFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	var serviceRecord Record
	if err := json.NewDecoder(s).Decode(&serviceRecord); err != nil {
		return nil, err
	}
	base.AddResultsForService(service, serviceRecord.Results, serviceRecord.CreationTime)
	return nil, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
