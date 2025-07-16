package customexporter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// metricsExporter implements the metrics exporter interfaces
type metricsExporter struct {
	config     *Config
	logger     *zap.Logger
	httpClient *http.Client
}

// logsExporter implements the logs exporter interfaces
type logsExporter struct {
	config     *Config
	logger     *zap.Logger
	httpClient *http.Client
}

// tracesExporter implements the traces exporter interfaces
type tracesExporter struct {
	config     *Config
	logger     *zap.Logger
	httpClient *http.Client
}

// ========================= METRICS EXPORTER =========================

// Start implements component.Component for metrics
func (e *metricsExporter) Start(ctx context.Context, host component.Host) error {
	e.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	
	e.logger.Info("Custom metrics exporter started",
		zap.String("endpoint", e.config.Endpoint),
		zap.Bool("enabled", e.config.Enabled),
		zap.String("encoding", e.getEncoding()),
		zap.String("compression", e.getCompression()),
		zap.Int("header_count", len(e.config.Headers)))
	return nil
}

// Shutdown implements component.Component for metrics
func (e *metricsExporter) Shutdown(ctx context.Context) error {
	e.logger.Info("Custom metrics exporter shutdown")
	return nil
}

// Capabilities implements the consumer interface for metrics
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
	err := e.exportMetricsToCustomEndpoint(ctx, md, metricCount, resourceMetrics.Len())
	if err != nil {
		e.logger.Error("Failed to export metrics", zap.Error(err))
		return err
	}

	e.logger.Info("Successfully exported metrics with actual data to custom endpoint")
	return nil
}

// exportMetricsToCustomEndpoint sends comprehensive metrics data to your Python server
func (e *metricsExporter) exportMetricsToCustomEndpoint(ctx context.Context, md pmetric.Metrics, metricCount, resourceCount int) error {
	// Create comprehensive metrics payload
	payload := map[string]interface{}{
		"type":               "metrics",
		"timestamp":          time.Now().Unix(),
		"source":             "custom-go-exporter",
		"metric_count":       metricCount,
		"resource_count":     resourceCount,
		"endpoint":           e.config.Endpoint,
		"custom_field":       e.config.CustomField,
		"encoding":           e.getEncoding(),
		"compression":        e.getCompression(),
		"kubernetes_summary": e.extractK8sSummaryFromMetrics(md),
		"resource_metrics":   e.extractResourceMetrics(md),
	}

	return e.sendToEndpoint(ctx, payload, "/custom-metrics")
}

// sendToEndpoint sends data to the Python server (metrics version)
func (e *metricsExporter) sendToEndpoint(ctx context.Context, payload map[string]interface{}, path string) error {
	// Convert to JSON (encoding support can be extended later)
	var data []byte
	var err error
	
	switch e.getEncoding() {
	case "json":
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload as JSON: %w", err)
		}
	default:
		// Default to JSON
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
	}

	// Apply compression if configured
	var requestBody []byte
	contentEncoding := ""
	
	switch e.getCompression() {
	case "gzip":
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		if _, err := gzipWriter.Write(data); err != nil {
			return fmt.Errorf("failed to gzip payload: %w", err)
		}
		if err := gzipWriter.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
		requestBody = buf.Bytes()
		contentEncoding = "gzip"
		
		e.logger.Debug("Applied gzip compression",
			zap.Int("original_size", len(data)),
			zap.Int("compressed_size", len(requestBody)),
			zap.Float64("compression_ratio", float64(len(requestBody))/float64(len(data))))
			
	case "none", "":
		requestBody = data
	default:
		e.logger.Warn("Unsupported compression type, using no compression",
			zap.String("compression", e.config.Compression))
		requestBody = data
	}

	// Log payload info
	e.logger.Debug("Sending metrics payload",
		zap.Int("payload_size_bytes", len(requestBody)),
		zap.String("path", path),
		zap.String("encoding", e.getEncoding()),
		zap.String("compression", contentEncoding))

	// Send to Python server
	url := "http://host.docker.internal:8080" + path
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set standard headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CustomGoExporter/2.1")
	req.Header.Set("X-Custom-Source", "kubernetes-collector")
	req.Header.Set("X-Metric-Count", fmt.Sprintf("%d", len(payload)))
	
	// Set compression header if applied
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	
	// Apply custom headers from configuration
	for key, value := range e.config.Headers {
		req.Header.Set(key, value)
		e.logger.Debug("Applied custom header", zap.String("header", key), zap.String("value", value))
	}

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
		zap.Int("payload_size", len(requestBody)),
		zap.String("content_encoding", contentEncoding))

	return nil
}

// getEncoding returns the configured encoding or default
func (e *metricsExporter) getEncoding() string {
	if e.config.Encoding == "" {
		return "json"
	}
	return e.config.Encoding
}

// getCompression returns the configured compression or default
func (e *metricsExporter) getCompression() string {
	if e.config.Compression == "" {
		return "none"
	}
	return e.config.Compression
}

// ========================= LOGS EXPORTER =========================

// Start implements component.Component for logs
func (e *logsExporter) Start(ctx context.Context, host component.Host) error {
	e.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	
	e.logger.Info("Custom logs exporter started",
		zap.String("endpoint", e.config.Endpoint),
		zap.Bool("enabled", e.config.Enabled),
		zap.String("encoding", e.getEncoding()),
		zap.String("compression", e.getCompression()),
		zap.Int("header_count", len(e.config.Headers)))
	return nil
}

// Shutdown implements component.Component for logs
func (e *logsExporter) Shutdown(ctx context.Context) error {
	e.logger.Info("Custom logs exporter shutdown")
	return nil
}

// Capabilities implements the consumer interface for logs
func (e *logsExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeLogs implements the logs consumer interface
func (e *logsExporter) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	if !e.config.Enabled {
		e.logger.Debug("Custom exporter disabled, skipping logs")
		return nil
	}

	// Count the logs for logging
	logCount := 0
	resourceLogs := ld.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		rl := resourceLogs.At(i)
		scopeLogs := rl.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			sl := scopeLogs.At(j)
			logCount += sl.LogRecords().Len()
		}
	}

	e.logger.Info("Custom exporter processing logs",
		zap.Int("log_count", logCount),
		zap.Int("resource_count", resourceLogs.Len()),
		zap.String("endpoint", e.config.Endpoint),
	)

	// Export the actual log data
	err := e.exportLogsToCustomEndpoint(ctx, ld, logCount, resourceLogs.Len())
	if err != nil {
		e.logger.Error("Failed to export logs", zap.Error(err))
		return err
	}

	e.logger.Info("Successfully exported logs with actual data to custom endpoint")
	return nil
}

// exportLogsToCustomEndpoint sends comprehensive logs data to your Python server
func (e *logsExporter) exportLogsToCustomEndpoint(ctx context.Context, ld plog.Logs, logCount, resourceCount int) error {
	// Create comprehensive logs payload
	payload := map[string]interface{}{
		"type":               "logs",
		"timestamp":          time.Now().Unix(),
		"source":             "custom-go-exporter",
		"log_count":          logCount,
		"resource_count":     resourceCount,
		"endpoint":           e.config.Endpoint,
		"custom_field":       e.config.CustomField,
		"encoding":           e.getEncoding(),
		"compression":        e.getCompression(),
		"kubernetes_summary": e.extractK8sSummaryFromLogs(ld),
		"resource_logs":      e.extractResourceLogs(ld),
	}

	return e.sendToEndpointLogs(ctx, payload, "/custom-logs")
}

// sendToEndpointLogs sends data to the Python server (logs version)
func (e *logsExporter) sendToEndpointLogs(ctx context.Context, payload map[string]interface{}, path string) error {
	// Convert to JSON (encoding support can be extended later)
	var data []byte
	var err error
	
	switch e.getEncoding() {
	case "json":
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal logs payload as JSON: %w", err)
		}
	default:
		// Default to JSON
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal logs payload: %w", err)
		}
	}

	// Apply compression if configured
	var requestBody []byte
	contentEncoding := ""
	
	switch e.getCompression() {
	case "gzip":
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		if _, err := gzipWriter.Write(data); err != nil {
			return fmt.Errorf("failed to gzip logs payload: %w", err)
		}
		if err := gzipWriter.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
		requestBody = buf.Bytes()
		contentEncoding = "gzip"
		
		e.logger.Debug("Applied gzip compression to logs",
			zap.Int("original_size", len(data)),
			zap.Int("compressed_size", len(requestBody)),
			zap.Float64("compression_ratio", float64(len(requestBody))/float64(len(data))))
			
	case "none", "":
		requestBody = data
	default:
		e.logger.Warn("Unsupported compression type, using no compression",
			zap.String("compression", e.config.Compression))
		requestBody = data
	}

	// Log payload info
	e.logger.Debug("Sending logs payload",
		zap.Int("payload_size_bytes", len(requestBody)),
		zap.String("path", path),
		zap.String("encoding", e.getEncoding()),
		zap.String("compression", contentEncoding))

	// Send to Python server
	url := "http://host.docker.internal:8080" + path
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set standard headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CustomGoExporter/2.1")
	req.Header.Set("X-Custom-Source", "kubernetes-collector")
	req.Header.Set("X-Log-Count", fmt.Sprintf("%d", len(payload)))
	
	// Set compression header if applied
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	
	// Apply custom headers from configuration
	for key, value := range e.config.Headers {
		req.Header.Set(key, value)
		e.logger.Debug("Applied custom header to logs", zap.String("header", key), zap.String("value", value))
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	e.logger.Debug("Successfully sent logs to custom endpoint",
		zap.String("url", url),
		zap.Int("status_code", resp.StatusCode),
		zap.Int("payload_size", len(requestBody)),
		zap.String("content_encoding", contentEncoding))

	return nil
}

// getEncoding returns the configured encoding or default (logs version)
func (e *logsExporter) getEncoding() string {
	if e.config.Encoding == "" {
		return "json"
	}
	return e.config.Encoding
}

// getCompression returns the configured compression or default (logs version)
func (e *logsExporter) getCompression() string {
	if e.config.Compression == "" {
		return "none"
	}
	return e.config.Compression
}

// ========================= TRACES EXPORTER =========================

// Start implements component.Component for traces
func (e *tracesExporter) Start(ctx context.Context, host component.Host) error {
	e.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	
	e.logger.Info("Custom traces exporter started",
		zap.String("endpoint", e.config.Endpoint),
		zap.Bool("enabled", e.config.Enabled),
		zap.String("encoding", e.getEncoding()),
		zap.String("compression", e.getCompression()),
		zap.Int("header_count", len(e.config.Headers)))
	return nil
}

// Shutdown implements component.Component for traces
func (e *tracesExporter) Shutdown(ctx context.Context) error {
	e.logger.Info("Custom traces exporter shutdown")
	return nil
}

// Capabilities implements the consumer interface for traces
func (e *tracesExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces implements the traces consumer interface
func (e *tracesExporter) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	if !e.config.Enabled {
		e.logger.Debug("Custom exporter disabled, skipping traces")
		return nil
	}

	// Count the traces for logging
	spanCount := 0
	resourceSpans := td.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		rs := resourceSpans.At(i)
		scopeSpans := rs.ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			ss := scopeSpans.At(j)
			spanCount += ss.Spans().Len()
		}
	}

	e.logger.Info("Custom exporter processing traces",
		zap.Int("span_count", spanCount),
		zap.Int("resource_count", resourceSpans.Len()),
		zap.String("endpoint", e.config.Endpoint),
	)

	// Export the actual trace data
	err := e.exportTracesToCustomEndpoint(ctx, td, spanCount, resourceSpans.Len())
	if err != nil {
		e.logger.Error("Failed to export traces", zap.Error(err))
		return err
	}

	e.logger.Info("Successfully exported traces with actual data to custom endpoint")
	return nil
}

// exportTracesToCustomEndpoint sends comprehensive traces data to your Python server
func (e *tracesExporter) exportTracesToCustomEndpoint(ctx context.Context, td ptrace.Traces, spanCount, resourceCount int) error {
	// Create comprehensive traces payload
	payload := map[string]interface{}{
		"type":               "traces",
		"timestamp":          time.Now().Unix(),
		"source":             "custom-go-exporter",
		"span_count":         spanCount,
		"resource_count":     resourceCount,
		"endpoint":           e.config.Endpoint,
		"custom_field":       e.config.CustomField,
		"encoding":           e.getEncoding(),
		"compression":        e.getCompression(),
		"kubernetes_summary": e.extractK8sSummaryFromTraces(td),
		"resource_traces":    e.extractResourceTraces(td),
	}

	return e.sendToEndpointTraces(ctx, payload, "/custom-traces")
}

// sendToEndpointTraces sends data to the Python server (traces version)
func (e *tracesExporter) sendToEndpointTraces(ctx context.Context, payload map[string]interface{}, path string) error {
	// Convert to JSON (encoding support can be extended later)
	var data []byte
	var err error
	
	switch e.getEncoding() {
	case "json":
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal traces payload as JSON: %w", err)
		}
	default:
		// Default to JSON
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal traces payload: %w", err)
		}
	}

	// Apply compression if configured
	var requestBody []byte
	contentEncoding := ""
	
	switch e.getCompression() {
	case "gzip":
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		if _, err := gzipWriter.Write(data); err != nil {
			return fmt.Errorf("failed to gzip traces payload: %w", err)
		}
		if err := gzipWriter.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
		requestBody = buf.Bytes()
		contentEncoding = "gzip"
		
		e.logger.Debug("Applied gzip compression to traces",
			zap.Int("original_size", len(data)),
			zap.Int("compressed_size", len(requestBody)),
			zap.Float64("compression_ratio", float64(len(requestBody))/float64(len(data))))
			
	case "none", "":
		requestBody = data
	default:
		e.logger.Warn("Unsupported compression type, using no compression",
			zap.String("compression", e.config.Compression))
		requestBody = data
	}

	// Log payload info
	e.logger.Debug("Sending traces payload",
		zap.Int("payload_size_bytes", len(requestBody)),
		zap.String("path", path),
		zap.String("encoding", e.getEncoding()),
		zap.String("compression", contentEncoding))

	// Send to Python server
	url := "http://host.docker.internal:8080" + path
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set standard headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CustomGoExporter/2.1")
	req.Header.Set("X-Custom-Source", "kubernetes-collector")
	req.Header.Set("X-Span-Count", fmt.Sprintf("%d", len(payload)))
	
	// Set compression header if applied
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	
	// Apply custom headers from configuration
	for key, value := range e.config.Headers {
		req.Header.Set(key, value)
		e.logger.Debug("Applied custom header to traces", zap.String("header", key), zap.String("value", value))
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	e.logger.Debug("Successfully sent traces to custom endpoint",
		zap.String("url", url),
		zap.Int("status_code", resp.StatusCode),
		zap.Int("payload_size", len(requestBody)),
		zap.String("content_encoding", contentEncoding))

	return nil
}

// getEncoding returns the configured encoding or default (traces version)
func (e *tracesExporter) getEncoding() string {
	if e.config.Encoding == "" {
		return "json"
	}
	return e.config.Encoding
}

// getCompression returns the configured compression or default (traces version)
func (e *tracesExporter) getCompression() string {
	if e.config.Compression == "" {
		return "none"
	}
	return e.config.Compression
}

// ========================= TRACES EXTRACTION FUNCTIONS =========================

// extractResourceTraces extracts traces in OTLP-like hierarchical structure
func (e *tracesExporter) extractResourceTraces(td ptrace.Traces) []map[string]interface{} {
	var resourceTraces []map[string]interface{}

	resourceSpansData := td.ResourceSpans()
	for i := 0; i < resourceSpansData.Len(); i++ {
		rs := resourceSpansData.At(i)
		
		// Extract and flatten resource attributes
		resourceAttrs := make(map[string]interface{})
		rs.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		// Extract scope spans
		var scopeSpans []map[string]interface{}
		scopeSpansData := rs.ScopeSpans()
		for j := 0; j < scopeSpansData.Len(); j++ {
			ss := scopeSpansData.At(j)
			
			// Get scope information
			scope := ss.Scope()
			scopeInfo := map[string]interface{}{
				"name":    scope.Name(),
				"version": scope.Version(),
			}

			// Extract spans for this scope
			var spans []map[string]interface{}
			spansData := ss.Spans()
			for k := 0; k < spansData.Len(); k++ {
				span := spansData.At(k)
				
				// Flatten span attributes
				attributes := make(map[string]interface{})
				span.Attributes().Range(func(key string, val pcommon.Value) bool {
					attributes[key] = val.AsString()
					return true
				})
				
				// Extract events
				events := make([]map[string]interface{}, span.Events().Len())
				for l := 0; l < span.Events().Len(); l++ {
					event := span.Events().At(l)
					eventAttrs := make(map[string]interface{})
					event.Attributes().Range(func(k string, v pcommon.Value) bool {
						eventAttrs[k] = v.AsString()
						return true
					})
					
					events[l] = map[string]interface{}{
						"name":              event.Name(),
						"timeUnixNano":      event.Timestamp(),
						"attributes":        eventAttrs,
						"droppedAttributesCount": event.DroppedAttributesCount(),
					}
				}
				
				// Extract links
				links := make([]map[string]interface{}, span.Links().Len())
				for l := 0; l < span.Links().Len(); l++ {
					link := span.Links().At(l)
					linkAttrs := make(map[string]interface{})
					link.Attributes().Range(func(k string, v pcommon.Value) bool {
						linkAttrs[k] = v.AsString()
						return true
					})
					
					links[l] = map[string]interface{}{
						"traceId":    link.TraceID().String(),
						"spanId":     link.SpanID().String(),
						"attributes": linkAttrs,
						"droppedAttributesCount": link.DroppedAttributesCount(),
					}
				}
				
				spanInfo := map[string]interface{}{
					"traceId":           span.TraceID().String(),
					"spanId":            span.SpanID().String(),
					"parentSpanId":      span.ParentSpanID().String(),
					"name":              span.Name(),
					"kind":              span.Kind().String(),
					"startTimeUnixNano": span.StartTimestamp(),
					"endTimeUnixNano":   span.EndTimestamp(),
					"attributes":        attributes,
					"events":            events,
					"links":             links,
					"status": map[string]interface{}{
						"code":    span.Status().Code().String(),
						"message": span.Status().Message(),
					},
					"droppedAttributesCount": span.DroppedAttributesCount(),
					"droppedEventsCount":     span.DroppedEventsCount(),
					"droppedLinksCount":      span.DroppedLinksCount(),
				}
				
				spans = append(spans, spanInfo)
			}

			scopeSpan := map[string]interface{}{
				"scope": scopeInfo,
				"spans": spans,
			}
			scopeSpans = append(scopeSpans, scopeSpan)
		}

		resourceTrace := map[string]interface{}{
			"attributes": resourceAttrs,
			"scopeSpans": scopeSpans,
		}
		resourceTraces = append(resourceTraces, resourceTrace)
	}

	return resourceTraces
}

// extractK8sSummaryFromTraces extracts Kubernetes-specific summary from traces
func (e *tracesExporter) extractK8sSummaryFromTraces(td ptrace.Traces) map[string]interface{} {
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

	resourceSpans := td.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		rs := resourceSpans.At(i)
		attrs := rs.Resource().Attributes()

		// Extract Kubernetes resource names
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

// ========================= LOGS EXTRACTION FUNCTIONS =========================

// extractResourceLogs extracts logs in OTLP-like hierarchical structure
func (e *logsExporter) extractResourceLogs(ld plog.Logs) []map[string]interface{} {
	var resourceLogs []map[string]interface{}

	resourceLogsData := ld.ResourceLogs()
	for i := 0; i < resourceLogsData.Len(); i++ {
		rl := resourceLogsData.At(i)
		
		// Extract and flatten resource attributes
		resourceAttrs := make(map[string]interface{})
		rl.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		// Extract scope logs
		var scopeLogs []map[string]interface{}
		scopeLogsData := rl.ScopeLogs()
		for j := 0; j < scopeLogsData.Len(); j++ {
			sl := scopeLogsData.At(j)
			
			// Get scope information
			scope := sl.Scope()
			scopeInfo := map[string]interface{}{
				"name":    scope.Name(),
				"version": scope.Version(),
			}

			// Extract log records for this scope
			var logRecords []map[string]interface{}
			logRecordsData := sl.LogRecords()
			for k := 0; k < logRecordsData.Len(); k++ {
				logRecord := logRecordsData.At(k)
				
				// Flatten log attributes
				attributes := make(map[string]interface{})
				logRecord.Attributes().Range(func(key string, val pcommon.Value) bool {
					attributes[key] = val.AsString()
					return true
				})
				
				logInfo := map[string]interface{}{
					"timeUnixNano":         logRecord.Timestamp(),
					"observedTimeUnixNano": logRecord.ObservedTimestamp(),
					"severityNumber":       logRecord.SeverityNumber(),
					"severityText":         logRecord.SeverityText(),
					"body":                 e.extractLogBody(logRecord.Body()),
					"attributes":           attributes,
					"traceId":              logRecord.TraceID().String(),
					"spanId":               logRecord.SpanID().String(),
					"flags":                logRecord.Flags(),
				}
				
				logRecords = append(logRecords, logInfo)
			}

			scopeLog := map[string]interface{}{
				"scope":      scopeInfo,
				"logRecords": logRecords,
			}
			scopeLogs = append(scopeLogs, scopeLog)
		}

		resourceLog := map[string]interface{}{
			"attributes": resourceAttrs,
			"scopeLogs":  scopeLogs,
		}
		resourceLogs = append(resourceLogs, resourceLog)
	}

	return resourceLogs
}

// extractLogBody extracts the log message body (FIXED API methods)
func (e *logsExporter) extractLogBody(body pcommon.Value) interface{} {
	switch body.Type() {
	case pcommon.ValueTypeStr:
		return body.AsString()
	case pcommon.ValueTypeInt:
		return body.Int() // FIXED: was IntValue()
	case pcommon.ValueTypeDouble:
		return body.Double() // FIXED: was DoubleValue()
	case pcommon.ValueTypeBool:
		return body.Bool() // FIXED: was BoolValue()
	case pcommon.ValueTypeMap:
		result := make(map[string]interface{})
		body.Map().Range(func(k string, v pcommon.Value) bool { // FIXED: was MapValue()
			result[k] = e.extractLogBody(v)
			return true
		})
		return result
	case pcommon.ValueTypeSlice:
		slice := body.Slice() // FIXED: was SliceValue()
		result := make([]interface{}, slice.Len())
		for i := 0; i < slice.Len(); i++ {
			result[i] = e.extractLogBody(slice.At(i))
		}
		return result
	default:
		return body.AsString()
	}
}

// extractK8sSummaryFromLogs extracts Kubernetes-specific summary from logs
func (e *logsExporter) extractK8sSummaryFromLogs(ld plog.Logs) map[string]interface{} {
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

	resourceLogs := ld.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		rl := resourceLogs.At(i)
		attrs := rl.Resource().Attributes()

		// Extract Kubernetes resource names
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

// ========================= METRICS EXTRACTION FUNCTIONS =========================

// extractResourceMetrics extracts metrics in OTLP-like hierarchical structure
func (e *metricsExporter) extractResourceMetrics(md pmetric.Metrics) []map[string]interface{} {
	var resourceMetrics []map[string]interface{}

	resourceMetricsData := md.ResourceMetrics()
	for i := 0; i < resourceMetricsData.Len(); i++ {
		rm := resourceMetricsData.At(i)
		
		// Extract and flatten resource attributes
		resourceAttrs := make(map[string]interface{})
		rm.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		// Extract scope metrics
		var scopeMetrics []map[string]interface{}
		scopeMetricsData := rm.ScopeMetrics()
		for j := 0; j < scopeMetricsData.Len(); j++ {
			sm := scopeMetricsData.At(j)
			
			// Get scope information
			scope := sm.Scope()
			scopeInfo := map[string]interface{}{
				"name":    scope.Name(),
				"version": scope.Version(),
			}

			// Extract metrics for this scope
			var metrics []map[string]interface{}
			metricsData := sm.Metrics()
			for k := 0; k < metricsData.Len(); k++ {
				metric := metricsData.At(k)
				
				metricInfo := map[string]interface{}{
					"name":        metric.Name(),
					"description": metric.Description(),
					"unit":        metric.Unit(),
					"type":        metric.Type().String(),
				}

				// Add the actual metric data based on type
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					metricInfo["gauge"] = e.extractGaugeData(metric.Gauge())
				case pmetric.MetricTypeSum:
					metricInfo["sum"] = e.extractSumData(metric.Sum())
				case pmetric.MetricTypeHistogram:
					metricInfo["histogram"] = e.extractHistogramData(metric.Histogram())
				case pmetric.MetricTypeSummary:
					metricInfo["summary"] = e.extractSummaryData(metric.Summary())
				}
				
				metrics = append(metrics, metricInfo)
			}

			scopeMetric := map[string]interface{}{
				"scope":   scopeInfo,
				"metrics": metrics,
			}
			scopeMetrics = append(scopeMetrics, scopeMetric)
		}

		resourceMetric := map[string]interface{}{
			"attributes":   resourceAttrs,
			"scopeMetrics": scopeMetrics,
		}
		resourceMetrics = append(resourceMetrics, resourceMetric)
	}

	return resourceMetrics
}

// extractGaugeData extracts gauge metric data in OTLP-like format
func (e *metricsExporter) extractGaugeData(gauge pmetric.Gauge) map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := gauge.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		// Flatten attributes
		attributes := make(map[string]interface{})
		point.Attributes().Range(func(k string, v pcommon.Value) bool {
			attributes[k] = v.AsString()
			return true
		})
		
		dataPoint := map[string]interface{}{
			"timeUnixNano": point.Timestamp(),
			"attributes":   attributes,
		}

		// Add value based on type
		switch point.ValueType() {
		case pmetric.NumberDataPointValueTypeInt:
			dataPoint["asInt"] = point.IntValue()
		case pmetric.NumberDataPointValueTypeDouble:
			dataPoint["asDouble"] = point.DoubleValue()
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return map[string]interface{}{
		"dataPoints": dataPoints,
	}
}

// extractSumData extracts sum metric data in OTLP-like format
func (e *metricsExporter) extractSumData(sum pmetric.Sum) map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := sum.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		// Flatten attributes
		attributes := make(map[string]interface{})
		point.Attributes().Range(func(k string, v pcommon.Value) bool {
			attributes[k] = v.AsString()
			return true
		})
		
		dataPoint := map[string]interface{}{
			"startTimeUnixNano": point.StartTimestamp(),
			"timeUnixNano":      point.Timestamp(),
			"attributes":        attributes,
		}

		// Add value based on type
		switch point.ValueType() {
		case pmetric.NumberDataPointValueTypeInt:
			dataPoint["asInt"] = point.IntValue()
		case pmetric.NumberDataPointValueTypeDouble:
			dataPoint["asDouble"] = point.DoubleValue()
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return map[string]interface{}{
		"dataPoints":              dataPoints,
		"isMonotonic":            sum.IsMonotonic(),
		"aggregationTemporality": sum.AggregationTemporality().String(),
	}
}

// extractHistogramData extracts histogram metric data in OTLP-like format
func (e *metricsExporter) extractHistogramData(histogram pmetric.Histogram) map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := histogram.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		// Flatten attributes
		attributes := make(map[string]interface{})
		point.Attributes().Range(func(k string, v pcommon.Value) bool {
			attributes[k] = v.AsString()
			return true
		})
		
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
			"startTimeUnixNano": point.StartTimestamp(),
			"timeUnixNano":      point.Timestamp(),
			"count":             point.Count(),
			"sum":               point.Sum(),
			"bucketCounts":      bucketCounts,
			"explicitBounds":    explicitBounds,
			"attributes":        attributes,
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

	return map[string]interface{}{
		"dataPoints":              dataPoints,
		"aggregationTemporality": histogram.AggregationTemporality().String(),
	}
}

// extractSummaryData extracts summary metric data in OTLP-like format
func (e *metricsExporter) extractSummaryData(summary pmetric.Summary) map[string]interface{} {
	var dataPoints []map[string]interface{}

	points := summary.DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		
		// Flatten attributes
		attributes := make(map[string]interface{})
		point.Attributes().Range(func(k string, v pcommon.Value) bool {
			attributes[k] = v.AsString()
			return true
		})
		
		// Extract quantile values
		var quantiles []map[string]interface{}
		for j := 0; j < point.QuantileValues().Len(); j++ {
			quantile := point.QuantileValues().At(j)
			quantiles = append(quantiles, map[string]interface{}{
				"quantile": quantile.Quantile(),
				"value":    quantile.Value(),
			})
		}
		
		dataPoint := map[string]interface{}{
			"startTimeUnixNano": point.StartTimestamp(),
			"timeUnixNano":      point.Timestamp(),
			"count":             point.Count(),
			"sum":               point.Sum(),
			"quantileValues":    quantiles,
			"attributes":        attributes,
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	return map[string]interface{}{
		"dataPoints": dataPoints,
	}
}

// extractK8sSummaryFromMetrics extracts Kubernetes-specific summary information from metrics
func (e *metricsExporter) extractK8sSummaryFromMetrics(md pmetric.Metrics) map[string]interface{} {
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

		// Extract Kubernetes resource names
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