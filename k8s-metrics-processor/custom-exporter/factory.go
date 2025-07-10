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
		component.MustNewType(typeStr), // Use MustNewType for newer versions
		createDefaultConfig,
		exporter.WithMetrics(createMetricsExporter, component.StabilityLevelDevelopment),
	)
}

// createDefaultConfig creates the default configuration for the exporter
func createDefaultConfig() component.Config {
	return &Config{
		Endpoint: "http://localhost:8080",
		Enabled:  true,
	}
}

// createMetricsExporter creates a metrics exporter based on the config
func createMetricsExporter(
	ctx context.Context,
	set exporter.Settings, // Use exporter.Settings for newer versions
	cfg component.Config,
) (exporter.Metrics, error) {
	config := cfg.(*Config)
	return &metricsExporter{
		config: config,
		logger: set.TelemetrySettings.Logger, // Logger is nested in TelemetrySettings
	}, nil
}