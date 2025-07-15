package customexporter

// Config defines configuration for the custom exporter
type Config struct {
	// Endpoint where to send the data
	Endpoint string `mapstructure:"endpoint"`
	
	// Enabled controls whether the exporter is active
	Enabled bool `mapstructure:"enabled"`
	
	// CustomField for future extensions
	CustomField string `mapstructure:"custom_field"`
	
	// Headers to include in HTTP requests
	Headers map[string]string `mapstructure:"headers"`
	
	// Encoding format for the payload (json, protobuf, etc.)
	Encoding string `mapstructure:"encoding"`
	
	// Compression type (none, gzip, deflate)
	Compression string `mapstructure:"compression"`
}