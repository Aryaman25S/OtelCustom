package customexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// metricsExporter implements the metrics exporter interfaces
type metricsExporter struct {
	config *Config
	logger *zap.Logger
}

// Start implements component.Component
func (e *metricsExporter) Start(ctx context.Context, host component.Host) error {
	e.logger.Info("Custom metrics exporter started",
		zap.String("endpoint", e.config.Endpoint),
		zap.Bool("enabled", e.config.Enabled))
	return nil
}

// Shutdown implements component.Component
func (e *metricsExporter) Shutdown(ctx context.Context) error {
	e.logger.Info("Custom metrics exporter shutdown")
	return nil
}

// Capabilities implements the consumer interface
func (e *metricsExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeMetrics implements the metrics consumer interface
func (e *metricsExporter) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	if !e.config.Enabled {
		e.logger.Debug("Custom exporter disabled, skipping metrics")
		return nil
	}

	// Count the metrics for logging
	metricCount := 0
	resourceMetrics := md.ResourceMetrics()
	for i := 0; i < resourceMetrics.Len(); i++ {
		rm := resourceMetrics.At(i)
		scopeMetrics := rm.ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			sm := scopeMetrics.At(j)
			metricCount += sm.Metrics().Len()
		}
	}

	e.logger.Info("Custom exporter processing metrics",
		zap.Int("metric_count", metricCount),
		zap.Int("resource_count", resourceMetrics.Len()),
		zap.String("endpoint", e.config.Endpoint),
	)

	// TODO: Add your custom processing logic here
	// Example: Access individual metrics
	for i := 0; i < resourceMetrics.Len(); i++ {
		rm := resourceMetrics.At(i)
		attrs := rm.Resource().Attributes()
		
		if nodeName, exists := attrs.Get("k8s.node.name"); exists {
			e.logger.Debug("Found Kubernetes node", 
				zap.String("node_name", nodeName.AsString()),
			)
		}
	}

	return nil
}