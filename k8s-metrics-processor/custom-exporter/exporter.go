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
		"actual_metrics":     e.extractActualMetrics(md),
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
		"actual_logs":        e.extractActualLogs(ld),
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

// ========================= LOGS EXTRACTION FUNCTIONS =========================

// extractActualLogs extracts complete log data including content, severity, and timestamps
func (e *logsExporter) extractActualLogs(ld plog.Logs) []map[string]interface{} {
	var actualLogs []map[string]interface{}

	resourceLogs := ld.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		rl := resourceLogs.At(i)
		
		// Extract resource attributes (pod name, namespace, etc.)
		resourceAttrs := make(map[string]string)
		rl.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		scopeLogs := rl.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			sl := scopeLogs.At(j)
			
			// Get scope information
			scope := sl.Scope()
			scopeInfo := map[string]string{
				"name":    scope.Name(),
				"version": scope.Version(),
			}

			logRecords := sl.LogRecords()
			for k := 0; k < logRecords.Len(); k++ {
				logRecord := logRecords.At(k)
				
				logData := map[string]interface{}{
					"timestamp":          logRecord.Timestamp(),
					"observed_timestamp": logRecord.ObservedTimestamp(),
					"severity_text":      logRecord.SeverityText(),
					"severity_number":    logRecord.SeverityNumber(),
					"body":               e.extractLogBody(logRecord.Body()),
					"resource":           resourceAttrs,
					"scope":              scopeInfo,
					"attributes":         e.extractAttributesLogs(logRecord.Attributes()),
					"trace_id":           logRecord.TraceID().String(),
					"span_id":            logRecord.SpanID().String(),
					"flags":              logRecord.Flags(),
				}
				
				actualLogs = append(actualLogs, logData)
			}
		}
	}

	return actualLogs
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

// extractAttributesLogs converts OTEL attributes to a string map (logs version)
func (e *logsExporter) extractAttributesLogs(attrs pcommon.Map) map[string]string {
	result := make(map[string]string)
	attrs.Range(func(k string, v pcommon.Value) bool {
		result[k] = v.AsString()
		return true
	})
	return result
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
		"actual_traces":      e.extractActualTraces(td),
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

// extractActualTraces extracts complete trace data including spans, timing, and attributes
func (e *tracesExporter) extractActualTraces(td ptrace.Traces) []map[string]interface{} {
	var actualTraces []map[string]interface{}

	resourceSpans := td.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		rs := resourceSpans.At(i)
		
		// Extract resource attributes (pod name, namespace, etc.)
		resourceAttrs := make(map[string]string)
		rs.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		scopeSpans := rs.ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			ss := scopeSpans.At(j)
			
			// Get scope information
			scope := ss.Scope()
			scopeInfo := map[string]string{
				"name":    scope.Name(),
				"version": scope.Version(),
			}

			spans := ss.Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				
				// Extract span events
				events := make([]map[string]interface{}, span.Events().Len())
				for l := 0; l < span.Events().Len(); l++ {
					event := span.Events().At(l)
					eventAttrs := make(map[string]string)
					event.Attributes().Range(func(k string, v pcommon.Value) bool {
						eventAttrs[k] = v.AsString()
						return true
					})
					
					events[l] = map[string]interface{}{
						"name":       event.Name(),
						"timestamp":  event.Timestamp(),
						"attributes": eventAttrs,
					}
				}
				
				// Extract span links
				links := make([]map[string]interface{}, span.Links().Len())
				for l := 0; l < span.Links().Len(); l++ {
					link := span.Links().At(l)
					linkAttrs := make(map[string]string)
					link.Attributes().Range(func(k string, v pcommon.Value) bool {
						linkAttrs[k] = v.AsString()
						return true
					})
					
					links[l] = map[string]interface{}{
						"trace_id":   link.TraceID().String(),
						"span_id":    link.SpanID().String(),
						"attributes": linkAttrs,
					}
				}
				
				spanData := map[string]interface{}{
					"trace_id":           span.TraceID().String(),
					"span_id":            span.SpanID().String(),
					"parent_span_id":     span.ParentSpanID().String(),
					"name":               span.Name(),
					"kind":               span.Kind().String(),
					"start_time":         span.StartTimestamp(),
					"end_time":           span.EndTimestamp(),
					"duration_ns":        span.EndTimestamp() - span.StartTimestamp(),
					"status_code":        span.Status().Code().String(),
					"status_message":     span.Status().Message(),
					"resource":           resourceAttrs,
					"scope":              scopeInfo,
					"attributes":         e.extractAttributesTraces(span.Attributes()),
					"events":             events,
					"links":              links,
				}
				
				actualTraces = append(actualTraces, spanData)
			}
		}
	}

	return actualTraces
}

// extractAttributesTraces converts OTEL attributes to a string map (traces version)
func (e *tracesExporter) extractAttributesTraces(attrs pcommon.Map) map[string]string {
	result := make(map[string]string)
	attrs.Range(func(k string, v pcommon.Value) bool {
		result[k] = v.AsString()
		return true
	})
	return result
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

// ========================= METRICS EXTRACTION FUNCTIONS =========================

// extractActualMetrics extracts complete metric data including names, values, and timestamps
func (e *metricsExporter) extractActualMetrics(md pmetric.Metrics) []map[string]interface{} {
	var actualMetrics []map[string]interface{}

	resourceMetrics := md.ResourceMetrics()
	for i := 0; i < resourceMetrics.Len(); i++ {
		rm := resourceMetrics.At(i)
		
		// Extract resource attributes (pod name, namespace, etc.)
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

// extractAttributes converts OTEL attributes to a string map
func (e *metricsExporter) extractAttributes(attrs pcommon.Map) map[string]string {
	result := make(map[string]string)
	attrs.Range(func(k string, v pcommon.Value) bool {
		result[k] = v.AsString()
		return true
	})
	return result
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