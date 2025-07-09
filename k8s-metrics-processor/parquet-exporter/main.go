// parquet-exporter/exporter.go
package parquetexporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// parquetExporter implements the exporter for converting telemetry data to Parquet
type parquetExporter struct {
	config *Config
	client *http.Client
	logger *zap.Logger
}

// MetricRecord represents a flattened metric record for Parquet
type MetricRecord struct {
	Timestamp         int64             `json:"timestamp"`
	MetricName        string            `json:"metric_name"`
	MetricType        string            `json:"metric_type"`
	Value             float64           `json:"value"`
	Unit              string            `json:"unit"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
	MetricAttributes  map[string]string `json:"metric_attributes"`
	ServiceName       string            `json:"service_name"`
	ServiceVersion    string            `json:"service_version"`
}

// LogRecord represents a flattened log record for Parquet
type LogRecord struct {
	Timestamp         int64             `json:"timestamp"`
	SeverityText      string            `json:"severity_text"`
	SeverityNumber    int32             `json:"severity_number"`
	Body              string            `json:"body"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
	LogAttributes     map[string]string `json:"log_attributes"`
	ServiceName       string            `json:"service_name"`
	TraceID           string            `json:"trace_id"`
	SpanID            string            `json:"span_id"`
}

// TraceRecord represents a flattened trace record for Parquet
type TraceRecord struct {
	Timestamp         int64             `json:"timestamp"`
	TraceID           string            `json:"trace_id"`
	SpanID            string            `json:"span_id"`
	ParentSpanID      string            `json:"parent_span_id"`
	SpanName          string            `json:"span_name"`
	SpanKind          string            `json:"span_kind"`
	Status            string            `json:"status"`
	Duration          int64             `json:"duration"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
	SpanAttributes    map[string]string `json:"span_attributes"`
	ServiceName       string            `json:"service_name"`
}

func (pe *parquetExporter) pushMetrics(ctx context.Context, md pmetric.Metrics) error {
	records := pe.convertMetricsToRecords(md)
	
	// For now, send as JSON instead of Parquet until we implement proper Parquet conversion
	jsonData, err := json.Marshal(records)
	if err != nil {
		pe.logger.Error("Failed to convert metrics to JSON", zap.Error(err))
		return err
	}
	
	return pe.sendData(ctx, jsonData, "metrics")
}

func (pe *parquetExporter) pushLogs(ctx context.Context, ld plog.Logs) error {
	records := pe.convertLogsToRecords(ld)
	
	jsonData, err := json.Marshal(records)
	if err != nil {
		pe.logger.Error("Failed to convert logs to JSON", zap.Error(err))
		return err
	}
	
	return pe.sendData(ctx, jsonData, "logs")
}

func (pe *parquetExporter) pushTraces(ctx context.Context, td ptrace.Traces) error {
	records := pe.convertTracesToRecords(td)
	
	jsonData, err := json.Marshal(records)
	if err != nil {
		pe.logger.Error("Failed to convert traces to JSON", zap.Error(err))
		return err
	}
	
	return pe.sendData(ctx, jsonData, "traces")
}

func (pe *parquetExporter) convertMetricsToRecords(md pmetric.Metrics) []MetricRecord {
	var records []MetricRecord
	
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		resourceAttrs := attributesToMap(rm.Resource().Attributes())
		serviceName := getServiceName(resourceAttrs)
		serviceVersion := getServiceVersion(resourceAttrs)
		
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					records = append(records, pe.processGaugeMetric(metric, resourceAttrs, serviceName, serviceVersion)...)
				case pmetric.MetricTypeSum:
					records = append(records, pe.processSumMetric(metric, resourceAttrs, serviceName, serviceVersion)...)
				case pmetric.MetricTypeHistogram:
					records = append(records, pe.processHistogramMetric(metric, resourceAttrs, serviceName, serviceVersion)...)
				}
			}
		}
	}
	
	return records
}

func (pe *parquetExporter) processGaugeMetric(metric pmetric.Metric, resourceAttrs map[string]string, serviceName, serviceVersion string) []MetricRecord {
	var records []MetricRecord
	
	for i := 0; i < metric.Gauge().DataPoints().Len(); i++ {
		dp := metric.Gauge().DataPoints().At(i)
		
		record := MetricRecord{
			Timestamp:         dp.Timestamp().AsTime().UnixNano(),
			MetricName:        metric.Name(),
			MetricType:        "gauge",
			Value:             getDataPointValue(dp),
			Unit:              metric.Unit(),
			ResourceAttributes: resourceAttrs,
			MetricAttributes:  attributesToMap(dp.Attributes()),
			ServiceName:       serviceName,
			ServiceVersion:    serviceVersion,
		}
		
		records = append(records, record)
	}
	
	return records
}

func (pe *parquetExporter) processSumMetric(metric pmetric.Metric, resourceAttrs map[string]string, serviceName, serviceVersion string) []MetricRecord {
	var records []MetricRecord
	
	for i := 0; i < metric.Sum().DataPoints().Len(); i++ {
		dp := metric.Sum().DataPoints().At(i)
		
		record := MetricRecord{
			Timestamp:         dp.Timestamp().AsTime().UnixNano(),
			MetricName:        metric.Name(),
			MetricType:        "sum",
			Value:             getDataPointValue(dp),
			Unit:              metric.Unit(),
			ResourceAttributes: resourceAttrs,
			MetricAttributes:  attributesToMap(dp.Attributes()),
			ServiceName:       serviceName,
			ServiceVersion:    serviceVersion,
		}
		
		records = append(records, record)
	}
	
	return records
}

func (pe *parquetExporter) processHistogramMetric(metric pmetric.Metric, resourceAttrs map[string]string, serviceName, serviceVersion string) []MetricRecord {
	var records []MetricRecord
	
	for i := 0; i < metric.Histogram().DataPoints().Len(); i++ {
		dp := metric.Histogram().DataPoints().At(i)
		
		// Create records for histogram count and sum
		countRecord := MetricRecord{
			Timestamp:         dp.Timestamp().AsTime().UnixNano(),
			MetricName:        metric.Name() + "_count",
			MetricType:        "histogram_count",
			Value:             float64(dp.Count()),
			Unit:              metric.Unit(),
			ResourceAttributes: resourceAttrs,
			MetricAttributes:  attributesToMap(dp.Attributes()),
			ServiceName:       serviceName,
			ServiceVersion:    serviceVersion,
		}
		
		sumRecord := MetricRecord{
			Timestamp:         dp.Timestamp().AsTime().UnixNano(),
			MetricName:        metric.Name() + "_sum",
			MetricType:        "histogram_sum",
			Value:             dp.Sum(),
			Unit:              metric.Unit(),
			ResourceAttributes: resourceAttrs,
			MetricAttributes:  attributesToMap(dp.Attributes()),
			ServiceName:       serviceName,
			ServiceVersion:    serviceVersion,
		}
		
		records = append(records, countRecord, sumRecord)
	}
	
	return records
}

func (pe *parquetExporter) convertLogsToRecords(ld plog.Logs) []LogRecord {
	var records []LogRecord
	
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		resourceAttrs := attributesToMap(rl.Resource().Attributes())
		serviceName := getServiceName(resourceAttrs)
		
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				
				record := LogRecord{
					Timestamp:         lr.Timestamp().AsTime().UnixNano(),
					SeverityText:      lr.SeverityText(),
					SeverityNumber:    int32(lr.SeverityNumber()),
					Body:              lr.Body().AsString(),
					ResourceAttributes: resourceAttrs,
					LogAttributes:     attributesToMap(lr.Attributes()),
					ServiceName:       serviceName,
					TraceID:           lr.TraceID().String(),
					SpanID:            lr.SpanID().String(),
				}
				
				records = append(records, record)
			}
		}
	}
	
	return records
}

func (pe *parquetExporter) convertTracesToRecords(td ptrace.Traces) []TraceRecord {
	var records []TraceRecord
	
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		resourceAttrs := attributesToMap(rs.Resource().Attributes())
		serviceName := getServiceName(resourceAttrs)
		
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			
			for k := 0; k < ss.Spans().Len(); k++ {
				span := ss.Spans().At(k)
				
				record := TraceRecord{
					Timestamp:         span.StartTimestamp().AsTime().UnixNano(),
					TraceID:           span.TraceID().String(),
					SpanID:            span.SpanID().String(),
					ParentSpanID:      span.ParentSpanID().String(),
					SpanName:          span.Name(),
					SpanKind:          span.Kind().String(),
					Status:            span.Status().Code().String(),
					Duration:          span.EndTimestamp().AsTime().UnixNano() - span.StartTimestamp().AsTime().UnixNano(),
					ResourceAttributes: resourceAttrs,
					SpanAttributes:    attributesToMap(span.Attributes()),
					ServiceName:       serviceName,
				}
				
				records = append(records, record)
			}
		}
	}
	
	return records
}

func (pe *parquetExporter) sendData(ctx context.Context, data []byte, dataType string) error {
	if len(data) == 0 {
		pe.logger.Debug("No data to send", zap.String("type", dataType))
		return nil
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", pe.config.Endpoint, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json") // Changed from parquet to JSON for now
	req.Header.Set("X-Data-Type", dataType)
	req.Header.Set("X-Format", pe.config.Format)
	
	for key, value := range pe.config.Headers {
		req.Header.Set(key, value)
	}
	
	// Send request
	resp, err := pe.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response status %d: %s", resp.StatusCode, string(body))
	}
	
	pe.logger.Debug("Successfully sent data", 
		zap.String("type", dataType), 
		zap.Int("size", len(data)),
		zap.Int("status", resp.StatusCode))
	
	return nil
}

// Helper functions
func attributesToMap(attrs pcommon.Map) map[string]string {
	result := make(map[string]string)
	attrs.Range(func(k string, v pcommon.Value) bool {
		result[k] = v.AsString()
		return true
	})
	return result
}

func getServiceName(attrs map[string]string) string {
	if name, exists := attrs["service.name"]; exists {
		return name
	}
	return "unknown"
}

func getServiceVersion(attrs map[string]string) string {
	if version, exists := attrs["service.version"]; exists {
		return version
	}
	return "unknown"
}

func getDataPointValue(dp pmetric.NumberDataPoint) float64 {
	switch dp.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return float64(dp.IntValue())
	case pmetric.NumberDataPointValueTypeDouble:
		return dp.DoubleValue()
	default:
		return 0.0
	}
}