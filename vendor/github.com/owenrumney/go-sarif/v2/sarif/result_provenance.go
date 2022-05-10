package sarif

import "time"

// ResultProvenance ...
type ResultProvenance struct {
	PropertyBag
	ConversionSources     []*PhysicalLocation `json:"conversionSources,omitempty"`
	FirstDetectionRunGUID *string             `json:"firstDetectionRunGuid,omitempty"`
	FirstDetectionTimeUTC *time.Time          `json:"firstDetectionTimeUtc,omitempty"`
	InvocationIndex       *int                `json:"invocationIndex,omitempty"`
	LastDetectionRunGUID  *string             `json:"lastDetectionRunGuid,omitempty"`
	LastDetectionTimeUTC  *time.Time          `json:"lastDetectionTimeUtc,omitempty"`
}

// NewResultProvenance creates a new ResultProvenance and returns a pointer to it
func NewResultProvenance() *ResultProvenance {
	return &ResultProvenance{}
}

// WithConversionSources sets the ConversionSources
func (resultProvenance *ResultProvenance) WithConversionSources(conversionSources []*PhysicalLocation) *ResultProvenance {
	resultProvenance.ConversionSources = conversionSources
	return resultProvenance
}

// AddConversionSource ...
func (resultProvenance *ResultProvenance) AddConversionSource(conversionSource *PhysicalLocation) {
	resultProvenance.ConversionSources = append(resultProvenance.ConversionSources, conversionSource)
}

// WithFirstDetectionRunGUID sets the FirstDetectionRunGUID
func (resultProvenance *ResultProvenance) WithFirstDetectionRunGUID(firstDetectionRunGUID string) *ResultProvenance {
	resultProvenance.FirstDetectionRunGUID = &firstDetectionRunGUID
	return resultProvenance
}

// WithFirstDetectionTimeUTC sets the FirstDetectionTimeUTC
func (resultProvenance *ResultProvenance) WithFirstDetectionTimeUTC(firstDetectionTimeUTC *time.Time) *ResultProvenance {
	resultProvenance.FirstDetectionTimeUTC = firstDetectionTimeUTC
	return resultProvenance
}

// WithInvocationIndex sets the InvocationIndex
func (resultProvenance *ResultProvenance) WithInvocationIndex(invocationIndex int) *ResultProvenance {
	resultProvenance.InvocationIndex = &invocationIndex
	return resultProvenance
}

// WithLastDetectionRunGUID sets the LastDetectionRunGUID
func (resultProvenance *ResultProvenance) WithLastDetectionRunGUID(lastDetectionRunGUID string) *ResultProvenance {
	resultProvenance.LastDetectionRunGUID = &lastDetectionRunGUID
	return resultProvenance
}

// WithLastDetectionTimeUTC sets the LastDetectionTimeUTC
func (resultProvenance *ResultProvenance) WithLastDetectionTimeUTC(lastDetectionTimeUTC *time.Time) *ResultProvenance {
	resultProvenance.LastDetectionTimeUTC = lastDetectionTimeUTC
	return resultProvenance
}
