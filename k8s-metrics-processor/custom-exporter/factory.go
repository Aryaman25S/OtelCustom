package customexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
)

const typeStr = "custom"

// NewFactory creates a factory for the custom exporter
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		exporter.WithMetrics(createMetricsExporter, component.StabilityLevelDevelopment),
		exporter.WithLogs(createLogsExporter, component.StabilityLevelDevelopment), // Add logs support
	)
}

// createDefaultConfig creates the default configuration for the exporter
func createDefaultConfig() component.Config {
	return &Config{
		Endpoint:    "http://localhost:8080",
		Enabled:     true,
		CustomField: "",
		Headers:     make(map[string]string), // Empty headers by default
		Encoding:    "json",                  // Default to JSON encoding
		Compression: "none",                  // Default to no compression
	}
}

// createMetricsExporter creates a metrics exporter based on the config
func createMetricsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Metrics, error) {
	config := cfg.(*Config)
	return &metricsExporter{
		config: config,
		logger: set.TelemetrySettings.Logger,
	}, nil
}

// createLogsExporter creates a logs exporter based on the config
func createLogsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Logs, error) {
	config := cfg.(*Config)
	return &logsExporter{
		config: config,
		logger: set.TelemetrySettings.Logger,
	}, nil
}