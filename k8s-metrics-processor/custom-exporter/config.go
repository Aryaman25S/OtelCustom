package customexporter

// Config defines configuration for the custom exporter
type Config struct {
	// Endpoint where to send the data (for future use)
	Endpoint string `mapstructure:"endpoint"`
	
	// Enabled controls whether the exporter is active
	Enabled bool `mapstructure:"enabled"`
	
	// CustomField for future extensions
	CustomField string `mapstructure:"custom_field"`
}