package sarif

// ConfigurationOverride ...
type ConfigurationOverride struct {
	Configuration *ReportingConfiguration       `json:"configuration,omitempty"`
	Descriptor    *ReportingDescriptorReference `json:"descriptor,omitempty"`
	PropertyBag

}

// NewConfigurationOverride creates a new ConfigurationOverride and returns a pointer to it
func NewConfigurationOverride() *ConfigurationOverride {
	return &ConfigurationOverride{}
}

// WithDescriptor sets the Descriptor
func (configurationOverride *ConfigurationOverride) WithDescriptor(descriptor *ReportingDescriptorReference) *ConfigurationOverride {
	configurationOverride.Descriptor = descriptor
	return configurationOverride
}

// WithConfiguration sets the Configuration
func (configurationOverride *ConfigurationOverride) WithConfiguration(configuration *ReportingConfiguration) *ConfigurationOverride {
	configurationOverride.Configuration = configuration
	return configurationOverride
}
