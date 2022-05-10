package sarif

// ReportingConfiguration ...
type ReportingConfiguration struct {
	Enabled    *bool        `json:"enabled,omitempty"`
	Level      string       `json:"level,omitempty"`
	Parameters *PropertyBag `json:"parameters,omitempty"`
	Rank       *float64     `json:"rank,omitempty"`
	PropertyBag

}

// NewReportingConfiguration creates a new ReportingConfiguration and returns a pointer to it
func NewReportingConfiguration() *ReportingConfiguration {
	return &ReportingConfiguration{}
}

// WithEnabled sets the Enabled
func (reportingConfiguration *ReportingConfiguration) WithEnabled(enabled bool) *ReportingConfiguration {
	reportingConfiguration.Enabled = &enabled
	return reportingConfiguration
}

// WithLevel sets the Level
func (reportingConfiguration *ReportingConfiguration) WithLevel(level string) *ReportingConfiguration {
	reportingConfiguration.Level = level
	return reportingConfiguration
}

// WithParameters sets the Parameters
func (reportingConfiguration *ReportingConfiguration) WithParameters(parameters *PropertyBag) *ReportingConfiguration {
	reportingConfiguration.Parameters = parameters
	return reportingConfiguration
}

// WithRank sets the Rank
func (reportingConfiguration *ReportingConfiguration) WithRank(rank float64) *ReportingConfiguration {
	reportingConfiguration.Rank = &rank
	return reportingConfiguration
}
