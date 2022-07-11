package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
)

const metadataFilename = "metadata.json"
const dataDirName = "data"

var cacheSubDir = "cloud"

var ErrCacheNotFound = fmt.Errorf("cache record not found")

func getServiceFilename(service string) string {
	return strings.NewReplacer(" ", "_", ".", "_").Replace(service) + ".json"
}

func getCacheDir(baseCacheDir, provider string) string {
	return filepath.Join(baseCacheDir, cacheSubDir, provider)
}

func (r *Report) Save(baseCacheDir string, cloudProvider string) error {

	cacheDir := getCacheDir(baseCacheDir, cloudProvider)

	if err := os.MkdirAll(cacheDir, 0777); err != nil { // all users can use the cache dir
		return err
	}

	reportDir := filepath.Join(cacheDir, r.AccountID, r.Region)

	dataDir := filepath.Join(reportDir, dataDirName)

	if err := os.MkdirAll(dataDir, 0700); err != nil { // only the current user is allowed to see this report
		return err
	}

	for _, service := range r.ServicesInScope {
		serviceFile := filepath.Join(dataDir, getServiceFilename(service))
		serviceReport := r.ForServices(service)
		s, err := os.Create(serviceFile)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(s).Encode(serviceReport); err != nil {
			return err
		}
	}

	metadataFile := filepath.Join(reportDir, metadataFilename)
	metadata := *r
	metadata.Results = make(types.Results, 0)
	m, err := os.Create(metadataFile)
	if err != nil {
		return err
	}
	return json.NewEncoder(m).Encode(metadata)
}

func LoadReport(baseCacheDir, cloudProvider, accountID, region string, services []string) (*Report, error) {

	cacheDir := getCacheDir(baseCacheDir, cloudProvider)

	reportDir := filepath.Join(cacheDir, accountID, region)
	metadataFile := filepath.Join(reportDir, metadataFilename)
	m, err := os.Open(metadataFile)
	if err != nil {
		return nil, ErrCacheNotFound
	}

	var report Report
	if err := json.NewDecoder(m).Decode(&report); err != nil {
		return nil, err
	}

	if len(services) == 0 {
		services = report.ServicesInScope
	}

	base := &Report{
		SchemaVersion:   schemaVersion,
		AccountID:       accountID,
		Results:         nil,
		ServicesInScope: report.ServicesInScope,
	}

	dataDir := filepath.Join(reportDir, dataDirName)

	for _, service := range services {
		if !contains(report.ServicesInScope, service) {
			continue
		}
		serviceFile := filepath.Join(dataDir, getServiceFilename(service))
		s, err := os.Open(serviceFile)
		if err != nil {
			return nil, err
		}
		var serviceReport Report
		if err := json.NewDecoder(s).Decode(&serviceReport); err != nil {
			return nil, err
		}
		base.Merge(&serviceReport, service)
	}

	return base, nil
}

func (r *Report) Merge(other *Report, servicesFromOther ...string) {
	if len(r.ServicesInScope) == 0 || len(other.ServicesInScope) == 0 {
		r.ServicesInScope = nil
	} else {
		for _, service := range other.ServicesInScope {
			for _, selected := range servicesFromOther {
				if selected == service {
					r.ServicesInScope = unique(append(r.ServicesInScope, service))
				}
			}
		}
	}
	r.Results = append(r.Results, other.ForServices(servicesFromOther...).Results...)
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func unique(s []string) []string {
	m := make(map[string]bool)
	for _, a := range s {
		m[a] = true
	}
	var r []string
	for a := range m {
		r = append(r, a)
	}
	return r
}
