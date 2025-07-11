package customexporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// metricsExporter implements the metrics exporter interfaces
type metricsExporter struct {
	config     *Config
	logger     *zap.Logger
	httpClient *http.Client
}

// Start implements component.Component
func (e *metricsExporter) Start(ctx context.Context, host component.Host) error {
	// Initialize HTTP client for sending data
	e.httpClient = &http.Client{
		Timeout: 30 * time.Second, // Increased timeout for larger payloads
	}
	
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

	// Export the actual metric data
	err := e.exportToCustomEndpoint(ctx, md, metricCount, resourceMetrics.Len())
	if err != nil {
		e.logger.Error("Failed to export metrics", zap.Error(err))
		return err
	}

	e.logger.Info("Successfully exported metrics with actual data to custom endpoint")
	return nil
}

// exportToCustomEndpoint sends comprehensive metrics data to your Python server
func (e *metricsExporter) exportToCustomEndpoint(ctx context.Context, md pmetric.Metrics, metricCount, resourceCount int) error {
	// Create comprehensive metrics payload
	payload := map[string]interface{}{
		"timestamp":      time.Now().Unix(),
		"source":         "custom-go-exporter",
		"metric_count":   metricCount,
		"resource_count": resourceCount,
		"endpoint":       e.config.Endpoint,
		"custom_field":   e.config.CustomField,
		"kubernetes_summary": e.extractK8sSummary(md),
		"actual_metrics":     e.extractActualMetrics(md), // Full metric data
	}

	// Convert to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics payload: %w", err)
	}

	// Log payload size
	e.logger.Debug("Sending metrics payload",
		zap.Int("payload_size_bytes", len(jsonData)),
		zap.Int("metric_count", metricCount))

	// Send to Python server
	url := "http://host.docker.internal:8080/custom-metrics"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CustomGoExporter/2.0")
	req.Header.Set("X-Custom-Source", "kubernetes-collector")
	req.Header.Set("X-Metric-Count", fmt.Sprintf("%d", metricCount))

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	e.logger.Debug("Successfully sent metrics to custom endpoint",
		zap.String("url", url),
		zap.Int("status_code", resp.StatusCode),
		zap.Int("payload_size", len(jsonData)))

	return nil
}

// extractActualMetrics extracts complete metric data including names, values, and timestamps
func (e *metricsExporter) extractActualMetrics(md pmetric.Metrics) []map[string]interface{} {
	var actualMetrics []map[string]interface{}

	resourceMetrics := md.ResourceMetrics()
	for i := 0; i < resourceMetrics.Len(); i++ {
		rm := resourceMetrics.At(i)
		
		// Extract resource attributes (pod name, namespace, etc.) - FIXED function signature
		resourceAttrs := make(map[string]string)
		rm.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		scopeMetrics := rm.ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			sm := scopeMetrics.At(j)
			
			// Get scope information
			scope := sm.Scope()
			scopeInfo := map[string]string{
				"name":    scope.Name(),
				"version": scope.Version(),
			}

			metrics := sm.Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				
				metricData := map[string]interface{}{
					"name":        metric.Name(),
					"description": metric.Description(),
					"unit":        metric.Unit(),
					"type":        metric.Type().String(),
					"resource":    resourceAttrs,
					"scope":       scopeInfo,
					"data_points": e.extractDataPoints(metric),
				}
				
				actualMetrics = append(actualMetrics, metricData)
			}
		}
	}

	return actualMetrics
}

// extractDataPoints extracts actual values from different metric types
func (e *metricsExporter) extractDataPoints(metric pmetric.Metric) []map[string]interface{} {
	var dataPoints []map[string]interface{}

	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dataPoints = e.extractGaugeDataPoints(metric.Gauge())
	case pmetric.MetricTypeSum:
		dataPoints = e.extractSumDataPoints(metric.Sum())
	case pmetric.MetricTypeHistogram:
		dataPoints = e.extractHistogramDataPoints(metric.Histogram())
	case pmetric.MetricTypeSummary:
		dataPoints = e.extractSummaryDataPoints(metric.Summary())
	default:
		e.logger.Debug("Unknown metric type", zap.String("type", metric.Type().String()))
	}

	return dataPoints
}

// extractGaugeDataPoints extracts data from gauge metrics (current value)
func (e *metricsExporter) extractGaugeDataPoints(gauge pmetric.Gauge) []map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := gauge.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		dataPoint := map[string]interface{}{
			"timestamp": point.Timestamp(),
			"value":     e.extractNumberValue(point),
			"attributes": e.extractAttributes(point.Attributes()),
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return dataPoints
}

// extractSumDataPoints extracts data from sum metrics (cumulative or delta)
func (e *metricsExporter) extractSumDataPoints(sum pmetric.Sum) []map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := sum.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		dataPoint := map[string]interface{}{
			"timestamp":    point.Timestamp(),
			"start_timestamp": point.StartTimestamp(),
			"value":        e.extractNumberValue(point),
			"attributes":   e.extractAttributes(point.Attributes()),
			"is_monotonic": sum.IsMonotonic(),
			"aggregation_temporality": sum.AggregationTemporality().String(),
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return dataPoints
}

// extractHistogramDataPoints extracts data from histogram metrics
func (e *metricsExporter) extractHistogramDataPoints(histogram pmetric.Histogram) []map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := histogram.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		// Extract bucket counts
		bucketCounts := make([]uint64, point.BucketCounts().Len())
		for j := 0; j < point.BucketCounts().Len(); j++ {
			bucketCounts[j] = point.BucketCounts().At(j)
		}
		
		// Extract explicit bounds
		explicitBounds := make([]float64, point.ExplicitBounds().Len())
		for j := 0; j < point.ExplicitBounds().Len(); j++ {
			explicitBounds[j] = point.ExplicitBounds().At(j)
		}
		
		dataPoint := map[string]interface{}{
			"timestamp":       point.Timestamp(),
			"start_timestamp": point.StartTimestamp(),
			"count":           point.Count(),
			"sum":             point.Sum(),
			"bucket_counts":   bucketCounts,
			"explicit_bounds": explicitBounds,
			"attributes":      e.extractAttributes(point.Attributes()),
		}
		
		// Add min/max if available
		if point.HasMin() {
			dataPoint["min"] = point.Min()
		}
		if point.HasMax() {
			dataPoint["max"] = point.Max()
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return dataPoints
}

// extractSummaryDataPoints extracts data from summary metrics
func (e *metricsExporter) extractSummaryDataPoints(summary pmetric.Summary) []map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := summary.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		// Extract quantile values
		quantiles := make([]map[string]interface{}, point.QuantileValues().Len())
		for j := 0; j < point.QuantileValues().Len(); j++ {
			quantile := point.QuantileValues().At(j)
			quantiles[j] = map[string]interface{}{
				"quantile": quantile.Quantile(),
				"value":    quantile.Value(),
			}
		}
		
		dataPoint := map[string]interface{}{
			"timestamp":       point.Timestamp(),
			"start_timestamp": point.StartTimestamp(),
			"count":           point.Count(),
			"sum":             point.Sum(),
			"quantiles":       quantiles,
			"attributes":      e.extractAttributes(point.Attributes()),
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return dataPoints
}

// extractNumberValue extracts numeric value from a number data point
func (e *metricsExporter) extractNumberValue(point pmetric.NumberDataPoint) interface{} {
	switch point.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return point.IntValue()
	case pmetric.NumberDataPointValueTypeDouble:
		return point.DoubleValue()
	default:
		return nil
	}
}

// extractAttributes converts OTEL attributes to a string map - FIXED to use pcommon.Map
func (e *metricsExporter) extractAttributes(attrs pcommon.Map) map[string]string {
	result := make(map[string]string)
	attrs.Range(func(k string, v pcommon.Value) bool {
		result[k] = v.AsString()
		return true
	})
	return result
}

// extractK8sSummary extracts Kubernetes-specific summary information
func (e *metricsExporter) extractK8sSummary(md pmetric.Metrics) map[string]interface{} {
	k8sSummary := map[string]interface{}{
		"nodes":       []string{},
		"pods":        []string{},
		"namespaces":  []string{},
		"deployments": []string{},
		"services":    []string{},
	}

	// Use maps as sets to deduplicate
	nodes := make(map[string]bool)
	pods := make(map[string]bool)
	namespaces := make(map[string]bool)
	deployments := make(map[string]bool)
	services := make(map[string]bool)

	resourceMetrics := md.ResourceMetrics()
	for i := 0; i < resourceMetrics.Len(); i++ {
		rm := resourceMetrics.At(i)
		attrs := rm.Resource().Attributes()

		// Extract Kubernetes resource names - FIXED to use proper API
		if nodeName, exists := attrs.Get("k8s.node.name"); exists {
			nodes[nodeName.AsString()] = true
		}
		if podName, exists := attrs.Get("k8s.pod.name"); exists {
			pods[podName.AsString()] = true
		}
		if namespace, exists := attrs.Get("k8s.namespace.name"); exists {
			namespaces[namespace.AsString()] = true
		}
		if deployment, exists := attrs.Get("k8s.deployment.name"); exists {
			deployments[deployment.AsString()] = true
		}
		if service, exists := attrs.Get("k8s.service.name"); exists {
			services[service.AsString()] = true
		}
	}

	// Convert maps to slices
	for node := range nodes {
		k8sSummary["nodes"] = append(k8sSummary["nodes"].([]string), node)
	}
	for pod := range pods {
		k8sSummary["pods"] = append(k8sSummary["pods"].([]string), pod)
	}
	for namespace := range namespaces {
		k8sSummary["namespaces"] = append(k8sSummary["namespaces"].([]string), namespace)
	}
	for deployment := range deployments {
		k8sSummary["deployments"] = append(k8sSummary["deployments"].([]string), deployment)
	}
	for service := range services {
		k8sSummary["services"] = append(k8sSummary["services"].([]string), service)
	}

	return k8sSummary
}