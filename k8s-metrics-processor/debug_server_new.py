#!/usr/bin/env python3

import gzip
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class FullTelemetryDebugHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path.startswith('/custom-metrics'):
            self.handle_custom_metrics()
        elif self.path.startswith('/custom-logs'):
            self.handle_custom_logs()
        elif self.path.startswith('/custom-traces'):
            self.handle_custom_traces()
        elif self.path.startswith('/v1/metrics'):
            self.handle_otlp_metrics()
        elif self.path.startswith('/v1/logs'):
            self.handle_otlp_logs()
        else:
            self.handle_unknown()

    def handle_custom_metrics(self):
        print(f"\n=== 📊 CUSTOM METRICS EXPORTER at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        print(f"Headers:")
        for header, value in self.headers.items():
            # Mask authorization tokens for security
            if header.lower() == 'authorization':
                print(f"  {header}: {value[:20]}***")
            else:
                print(f"  {header}: {value}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        # Handle compression
        data_to_parse = self.handle_compression(raw_body)
        
        try:
            data = json.loads(data_to_parse.decode('utf-8'))
            print(f"\n📊 METRICS DATA:")
            print(f"  Source: {data.get('source', 'unknown')}")
            print(f"  Type: {data.get('type', 'unknown')}")
            print(f"  Timestamp: {datetime.fromtimestamp(data.get('timestamp', 0))}")
            print(f"  Metric Count: {data.get('metric_count', 0)}")
            print(f"  Resource Count: {data.get('resource_count', 0)}")
            print(f"  Original Payload Size: {len(raw_body)} bytes")
            print(f"  Decompressed Size: {len(data_to_parse)} bytes")
            print(f"  Custom Field: {data.get('custom_field', 'N/A')}")
            print(f"  Encoding: {data.get('encoding', 'N/A')}")
            print(f"  Compression: {data.get('compression', 'N/A')}")
            
            # Show compression ratio if compressed
            if len(raw_body) != len(data_to_parse):
                ratio = len(raw_body) / len(data_to_parse)
                print(f"  Compression Ratio: {ratio:.2f} ({ratio*100:.1f}% of original size)")
            
            k8s_data = data.get('kubernetes_summary', {})
            print(f"  Kubernetes Summary:")
            print(f"    Nodes: {k8s_data.get('nodes', [])}")
            print(f"    Namespaces: {k8s_data.get('namespaces', [])}")
            print(f"    Pods: {len(k8s_data.get('pods', []))} pods")
            print(f"    Deployments: {len(k8s_data.get('deployments', []))} deployments")
            print(f"    Services: {len(k8s_data.get('services', []))} services")
            
            actual_metrics = data.get('resource_metrics', [])
            print(f"\n📈 RESOURCE METRICS ({len(actual_metrics)} resource groups):")
            print("=" * 80)
            
            total_metrics = 0
            # Show first few resource groups as examples
            for i, resource_group in enumerate(actual_metrics[:3]):
                attributes = resource_group.get('attributes', {})
                scope_metrics = resource_group.get('scopeMetrics', [])
                
                print(f"\nResource Group {i+1}:")
                # Show key resource attributes
                if 'k8s.pod.name' in attributes:
                    print(f"  Pod: {attributes.get('k8s.pod.name')}")
                elif 'k8s.node.name' in attributes:
                    print(f"  Node: {attributes.get('k8s.node.name')}")
                elif 'k8s.namespace.name' in attributes:
                    print(f"  Namespace: {attributes.get('k8s.namespace.name')}")
                
                print(f"  Scope Groups: {len(scope_metrics)}")
                
                # Count metrics in this resource group
                resource_metric_count = 0
                for scope_group in scope_metrics:
                    metrics = scope_group.get('metrics', [])
                    resource_metric_count += len(metrics)
                    
                    # Show first few metrics from first scope
                    if i == 0 and scope_group == scope_metrics[0]:
                        print(f"  Sample Metrics from this resource:")
                        for j, metric in enumerate(metrics[:3]):
                            print(f"    • {metric.get('name', 'Unknown')} ({metric.get('type', 'Unknown')})")
                            if j >= 2:
                                remaining = len(metrics) - 3
                                if remaining > 0:
                                    print(f"    • ... and {remaining} more metrics")
                                break
                
                print(f"  Total Metrics: {resource_metric_count}")
                total_metrics += resource_metric_count
                
            if len(actual_metrics) > 3:
                print(f"\n... and {len(actual_metrics) - 3} more resource groups")
            
            print(f"\n📊 SUMMARY: {total_metrics} total metrics across {len(actual_metrics)} resource groups")
            
        except Exception as e:
            print(f"Error parsing metrics data: {e}")
        
        print("\n=== END METRICS ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "success", "source": "metrics_handler"}
        self.wfile.write(json.dumps(response).encode())

    def handle_custom_logs(self):
        print(f"\n=== 📝 CUSTOM LOGS EXPORTER at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        print(f"Headers:")
        for header, value in self.headers.items():
            # Mask authorization tokens for security
            if header.lower() == 'authorization':
                print(f"  {header}: {value[:20]}***")
            else:
                print(f"  {header}: {value}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        # Handle compression
        data_to_parse = self.handle_compression(raw_body)
        
        try:
            data = json.loads(data_to_parse.decode('utf-8'))
            print(f"\n📝 LOGS DATA:")
            print(f"  Source: {data.get('source', 'unknown')}")
            print(f"  Type: {data.get('type', 'unknown')}")
            print(f"  Timestamp: {datetime.fromtimestamp(data.get('timestamp', 0))}")
            print(f"  Log Count: {data.get('log_count', 0)}")
            print(f"  Resource Count: {data.get('resource_count', 0)}")
            print(f"  Original Payload Size: {len(raw_body)} bytes")
            print(f"  Decompressed Size: {len(data_to_parse)} bytes")
            print(f"  Custom Field: {data.get('custom_field', 'N/A')}")
            print(f"  Encoding: {data.get('encoding', 'N/A')}")
            print(f"  Compression: {data.get('compression', 'N/A')}")
            
            # Show compression ratio if compressed
            if len(raw_body) != len(data_to_parse):
                ratio = len(raw_body) / len(data_to_parse)
                print(f"  Compression Ratio: {ratio:.2f} ({ratio*100:.1f}% of original size)")
            
            k8s_data = data.get('kubernetes_summary', {})
            print(f"  Kubernetes Summary:")
            print(f"    Nodes: {k8s_data.get('nodes', [])}")
            print(f"    Namespaces: {k8s_data.get('namespaces', [])}")
            print(f"    Pods: {len(k8s_data.get('pods', []))} pods")
            print(f"    Deployments: {len(k8s_data.get('deployments', []))} deployments")
            print(f"    Services: {len(k8s_data.get('services', []))} services")
            
            actual_logs = data.get('resource_logs', [])
            print(f"\n📋 RESOURCE LOGS ({len(actual_logs)} resource groups):")
            print("=" * 100)
            
            total_logs = 0
            all_logs_flat = []
            
            # Flatten logs for analysis
            for resource_group in actual_logs:
                attributes = resource_group.get('attributes', {})
                scope_logs = resource_group.get('scopeLogs', [])
                
                for scope_group in scope_logs:
                    log_records = scope_group.get('logRecords', [])
                    for log_record in log_records:
                        # Add resource attributes to each log for easier processing
                        log_record['resource_attributes'] = attributes
                        all_logs_flat.append(log_record)
                        total_logs += 1
            
            # Group logs by severity
            log_levels = {}
            for log in all_logs_flat:
                severity = log.get('severityText', 'UNKNOWN')
                if severity not in log_levels:
                    log_levels[severity] = []
                log_levels[severity].append(log)
            
            print(f"\n📊 LOG LEVEL BREAKDOWN:")
            for level, logs in sorted(log_levels.items()):
                print(f"  {level}: {len(logs)} logs")
            
            print(f"\n📋 RECENT LOG ENTRIES:")
            print("-" * 100)
            
            for i, log in enumerate(all_logs_flat[:10]):  # Show first 10 logs
                # Convert timestamp
                timestamp = log.get('timeUnixNano', 0)
                if timestamp and timestamp > 0:
                    if timestamp > 1e15:  # nanoseconds
                        timestamp_secs = timestamp / 1e9
                    else:
                        timestamp_secs = timestamp
                    log_time = datetime.fromtimestamp(timestamp_secs)
                else:
                    log_time = "Unknown time"
                
                # Extract log details
                severity = log.get('severityText', 'INFO')
                body = log.get('body', 'No message')
                resource_attrs = log.get('resource_attributes', {})
                
                # Format resource info
                resource_info = []
                if 'k8s.pod.name' in resource_attrs:
                    resource_info.append(f"Pod: {resource_attrs['k8s.pod.name']}")
                if 'k8s.namespace.name' in resource_attrs:
                    resource_info.append(f"NS: {resource_attrs['k8s.namespace.name']}")
                if 'k8s.node.name' in resource_attrs:
                    resource_info.append(f"Node: {resource_attrs['k8s.node.name']}")
                
                resource_str = " | ".join(resource_info) if resource_info else "Unknown resource"
                
                print(f"\nLog {i+1}: [{severity}] {log_time}")
                print(f"  Resource: {resource_str}")
                print(f"  Message: {body}")
                
                # Show attributes if present
                attributes = log.get('attributes', {})
                if attributes:
                    attr_str = ", ".join([f"{k}:{v}" for k, v in attributes.items() if str(k).startswith('k8s.')])
                    if attr_str:
                        print(f"  K8s Attributes: {attr_str}")
                
                # Show trace information if present
                trace_id = log.get('traceId', '')
                span_id = log.get('spanId', '')
                if trace_id and trace_id != '00000000000000000000000000000000':
                    print(f"  Trace ID: {trace_id}")
                if span_id and span_id != '0000000000000000':
                    print(f"  Span ID: {span_id}")
                
                print("-" * 100)
                
                # Limit to first 10 logs for readability
                if i >= 9:
                    remaining = len(all_logs_flat) - 10
                    if remaining > 0:
                        print(f"\n... and {remaining} more log entries")
                    break
            
            print(f"\n📈 LOG STATISTICS:")
            severity_counts = {}
            namespaces = set()
            pods = set()
            
            for log in all_logs_flat:
                severity = log.get('severityText', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                resource_attrs = log.get('resource_attributes', {})
                if 'k8s.namespace.name' in resource_attrs:
                    namespaces.add(resource_attrs['k8s.namespace.name'])
                if 'k8s.pod.name' in resource_attrs:
                    pods.add(resource_attrs['k8s.pod.name'])
            
            print(f"  Severity Distribution: {severity_counts}")
            print(f"  Unique Namespaces: {len(namespaces)} ({list(namespaces)})")
            print(f"  Unique Pods: {len(pods)}")
            print(f"  Total Resource Groups: {len(actual_logs)}")
            print(f"  Total Log Records: {total_logs}")
            
        except Exception as e:
            print(f"Error parsing logs data: {e}")
            print(f"Raw body size: {len(raw_body)} bytes")
            if len(raw_body) < 1000:
                print(f"Raw body: {raw_body}")
        
        print("\n=== END LOGS ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "success", "source": "logs_handler", "logs_processed": total_logs if 'total_logs' in locals() else 0}
        self.wfile.write(json.dumps(response).encode())

    def handle_custom_traces(self):
        print(f"\n=== 🔗 CUSTOM TRACES EXPORTER at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        print(f"Headers:")
        for header, value in self.headers.items():
            # Mask authorization tokens for security
            if header.lower() == 'authorization':
                print(f"  {header}: {value[:20]}***")
            else:
                print(f"  {header}: {value}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        # Handle compression
        data_to_parse = self.handle_compression(raw_body)
        
        try:
            data = json.loads(data_to_parse.decode('utf-8'))
            print(f"\n🔗 TRACES DATA:")
            print(f"  Source: {data.get('source', 'unknown')}")
            print(f"  Type: {data.get('type', 'unknown')}")
            print(f"  Timestamp: {datetime.fromtimestamp(data.get('timestamp', 0))}")
            print(f"  Span Count: {data.get('span_count', 0)}")
            print(f"  Resource Count: {data.get('resource_count', 0)}")
            print(f"  Original Payload Size: {len(raw_body)} bytes")
            print(f"  Decompressed Size: {len(data_to_parse)} bytes")
            print(f"  Custom Field: {data.get('custom_field', 'N/A')}")
            print(f"  Encoding: {data.get('encoding', 'N/A')}")
            print(f"  Compression: {data.get('compression', 'N/A')}")
            
            # Show compression ratio if compressed
            if len(raw_body) != len(data_to_parse):
                ratio = len(raw_body) / len(data_to_parse)
                print(f"  Compression Ratio: {ratio:.2f} ({ratio*100:.1f}% of original size)")
            
            k8s_data = data.get('kubernetes_summary', {})
            print(f"  Kubernetes Summary:")
            print(f"    Nodes: {k8s_data.get('nodes', [])}")
            print(f"    Namespaces: {k8s_data.get('namespaces', [])}")
            print(f"    Pods: {len(k8s_data.get('pods', []))} pods")
            print(f"    Deployments: {len(k8s_data.get('deployments', []))} deployments")
            print(f"    Services: {len(k8s_data.get('services', []))} services")
            
            actual_traces = data.get('resource_traces', [])
            print(f"\n🔗 RESOURCE TRACES ({len(actual_traces)} resource groups):")
            print("=" * 100)
            
            total_spans = 0
            all_spans_flat = []
            
            # Flatten spans for analysis
            for resource_group in actual_traces:
                attributes = resource_group.get('attributes', {})
                scope_spans = resource_group.get('scopeSpans', [])
                
                for scope_group in scope_spans:
                    spans = scope_group.get('spans', [])
                    for span in spans:
                        # Add resource attributes to each span for easier processing
                        span['resource_attributes'] = attributes
                        all_spans_flat.append(span)
                        total_spans += 1
            
            # Group spans by trace ID
            trace_groups = {}
            services = {}
            status_counts = {}
            
            for span in all_spans_flat:
                # Group by trace ID
                trace_id = span.get('traceId', 'unknown')
                if trace_id not in trace_groups:
                    trace_groups[trace_id] = []
                trace_groups[trace_id].append(span)
                
                # Count by service
                service_name = span.get('resource_attributes', {}).get('service.name', 'unknown-service')
                if service_name not in services:
                    services[service_name] = 0
                services[service_name] += 1
                
                # Count by status
                status = span.get('status', {}).get('code', 'UNSET')
                status_counts[status] = status_counts.get(status, 0) + 1
            
            print(f"\n📊 TRACE SUMMARY:")
            print(f"  Total Unique Traces: {len(trace_groups)}")
            print(f"  Total Spans: {len(all_spans_flat)}")
            print(f"  Average Spans per Trace: {len(all_spans_flat) / len(trace_groups) if trace_groups else 0:.1f}")
            print(f"  Status Distribution: {status_counts}")
            
            # Show service breakdown
            print(f"  Services ({len(services)}):")
            for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
                print(f"    {service}: {count} spans")
            
            print(f"\n🔗 SAMPLE TRACES:")
            print("-" * 100)
            
            # Show first few complete traces
            traces_shown = 0
            for trace_id, spans in list(trace_groups.items())[:3]:  # Show first 3 traces
                traces_shown += 1
                print(f"\nTrace {traces_shown}: {trace_id}")
                print(f"  Spans: {len(spans)}")
                
                # Sort spans by start time
                sorted_spans = sorted(spans, key=lambda s: s.get('startTimeUnixNano', 0))
                
                # Calculate trace duration
                if sorted_spans:
                    trace_start = sorted_spans[0].get('startTimeUnixNano', 0)
                    trace_end = max(span.get('endTimeUnixNano', 0) for span in sorted_spans)
                    trace_duration_ms = (trace_end - trace_start) / 1_000_000 if trace_end > trace_start else 0
                    print(f"  Total Duration: {trace_duration_ms:.2f}ms")
                
                for i, span in enumerate(sorted_spans[:5]):  # Show first 5 spans per trace
                    # Calculate span duration
                    start_time = span.get('startTimeUnixNano', 0)
                    end_time = span.get('endTimeUnixNano', 0)
                    duration_ms = (end_time - start_time) / 1_000_000 if end_time > start_time else 0
                    
                    # Extract key attributes
                    resource_attrs = span.get('resource_attributes', {})
                    span_attrs = span.get('attributes', {})
                    
                    # Format span info
                    service_name = resource_attrs.get('service.name', 'unknown-service')
                    operation_name = span.get('name', 'unknown-operation')
                    status = span.get('status', {}).get('code', 'UNSET')
                    
                    # Show indentation for child spans
                    parent_span_id = span.get('parentSpanId', '0000000000000000')
                    indent = "    " if parent_span_id != '0000000000000000' else "  "
                    
                    print(f"{indent}Span {i+1}: {operation_name}")
                    print(f"{indent}  Service: {service_name}")
                    print(f"{indent}  Kind: {span.get('kind', 'INTERNAL')}")
                    print(f"{indent}  Duration: {duration_ms:.2f}ms")
                    print(f"{indent}  Status: {status}")
                    
                    # Show status message if error
                    status_message = span.get('status', {}).get('message')
                    if status_message and status == 'ERROR':
                        print(f"{indent}  Error: {status_message}")
                    
                    # Show key HTTP/DB attributes
                    key_attrs = {}
                    for key in ['http.method', 'http.url', 'http.status_code', 'db.statement', 'db.system']:
                        if key in span_attrs:
                            key_attrs[key] = span_attrs[key]
                    
                    if key_attrs:
                        attr_str = ", ".join([f"{k}={v}" for k, v in key_attrs.items()])
                        print(f"{indent}  Attributes: {attr_str}")
                    
                    # Show events if any
                    events = span.get('events', [])
                    if events:
                        print(f"{indent}  Events: {len(events)} events")
                        for event in events[:2]:  # Show first 2 events
                            event_name = event.get('name', 'unnamed-event')
                            print(f"{indent}    - {event_name}")
                    
                    # Show links if any
                    links = span.get('links', [])
                    if links:
                        print(f"{indent}  Links: {len(links)} links to other traces")
                
                if len(sorted_spans) > 5:
                    remaining = len(sorted_spans) - 5
                    print(f"  ... and {remaining} more spans in this trace")
                
                print("-" * 100)
            
            if len(trace_groups) > 3:
                remaining = len(trace_groups) - 3
                print(f"\n... and {remaining} more traces")
            
            print(f"\n📈 TRACE STATISTICS:")
            
            # Error analysis
            error_spans = [span for span in all_spans_flat if span.get('status', {}).get('code') == 'ERROR']
            error_rate = (len(error_spans) / len(all_spans_flat) * 100) if all_spans_flat else 0
            
            # Duration analysis
            total_duration = sum((span.get('endTimeUnixNano', 0) - span.get('startTimeUnixNano', 0)) 
                               for span in all_spans_flat if span.get('endTimeUnixNano', 0) > span.get('startTimeUnixNano', 0))
            avg_duration = (total_duration / len(all_spans_flat) / 1_000_000) if all_spans_flat else 0
            
            print(f"  Error Rate: {error_rate:.1f}% ({len(error_spans)} error spans)")
            print(f"  Average Span Duration: {avg_duration:.2f}ms")
            
            # Unique Kubernetes resources
            namespaces = set()
            pods = set()
            
            for span in all_spans_flat:
                resource_attrs = span.get('resource_attributes', {})
                if 'k8s.namespace.name' in resource_attrs:
                    namespaces.add(resource_attrs['k8s.namespace.name'])
                if 'k8s.pod.name' in resource_attrs:
                    pods.add(resource_attrs['k8s.pod.name'])
            
            print(f"  Unique Namespaces: {len(namespaces)} ({list(namespaces)})")
            print(f"  Unique Pods: {len(pods)}")
            print(f"  Total Resource Groups: {len(actual_traces)}")
            print(f"  Total Spans: {total_spans}")
            
        except Exception as e:
            print(f"Error parsing traces data: {e}")
            print(f"Raw body size: {len(raw_body)} bytes")
            if len(raw_body) < 1000:
                print(f"Raw body: {raw_body}")
        
        print("\n=== END TRACES ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "success", "source": "traces_handler", "spans_processed": total_spans if 'total_spans' in locals() else 0}
        self.wfile.write(json.dumps(response).encode())

    def handle_compression(self, raw_body):
        """Handle different compression types and return decompressed data"""
        content_encoding = self.headers.get('Content-Encoding', '').lower()
        
        if content_encoding == 'gzip' or (len(raw_body) >= 2 and raw_body[0] == 0x1f and raw_body[1] == 0x8b):
            print(f"  🗜️ Data is GZIP compressed - decompressing...")
            try:
                decompressed = gzip.decompress(raw_body)
                print(f"  ✅ Successfully decompressed {len(raw_body)} -> {len(decompressed)} bytes")
                return decompressed
            except Exception as e:
                print(f"  ❌ Failed to decompress gzip data: {e}")
                return raw_body
        elif content_encoding == 'deflate':
            print(f"  🗜️ Data is DEFLATE compressed - decompressing...")
            try:
                import zlib
                decompressed = zlib.decompress(raw_body)
                print(f"  ✅ Successfully decompressed {len(raw_body)} -> {len(decompressed)} bytes")
                return decompressed
            except Exception as e:
                print(f"  ❌ Failed to decompress deflate data: {e}")
                return raw_body
        else:
            print(f"  📄 Data is not compressed (Content-Encoding: {content_encoding or 'none'})")
            return raw_body

    def handle_otlp_metrics(self):
        print(f"\n=== OTLP HTTP METRICS at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        print(f"Body size: {len(raw_body)} bytes")
        
        # Handle compression
        body = self.handle_compression(raw_body)
        
        try:
            text_content = body.decode('utf-8')
            print(f"OTLP Content (first 300 chars): {text_content[:300]}...")
            
            if text_content.strip().startswith('{'):
                try:
                    data = json.loads(text_content)
                    if 'resourceMetrics' in data:
                        metrics = data['resourceMetrics']
                        print(f"OTLP Resource metrics count: {len(metrics)}")
                        
                        total_data_points = 0
                        for resource_metric in metrics:
                            scope_metrics = resource_metric.get('scopeMetrics', [])
                            for scope_metric in scope_metrics:
                                metrics_list = scope_metric.get('metrics', [])
                                total_data_points += len(metrics_list)
                        
                        print(f"Total OTLP data points: {total_data_points}")
                except json.JSONDecodeError:
                    print("Invalid JSON in OTLP data")
                    
        except UnicodeDecodeError:
            print(f"Binary OTLP data - {len(raw_body)} bytes")
        
        print("=== END OTLP METRICS ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "source": "otlp_handler"}')

    def handle_otlp_logs(self):
        print(f"\n=== OTLP LOGS at {datetime.now()} ===")
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        print(f"Logs body size: {len(raw_body)} bytes")
        print("=== END OTLP LOGS ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "source": "logs_handler"}')

    def handle_unknown(self):
        print(f"\n=== UNKNOWN ENDPOINT at {datetime.now()} ===")
        print(f"Path: {self.path}")
        print("=== END UNKNOWN ===\n")
        
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

def main():
    port = 8080
    server = HTTPServer(('', port), FullTelemetryDebugHandler)
    print(f"📊📝🔗 FULL TELEMETRY Debug Server v5.0 listening on port {port}")
    print(f"📊 Custom Metrics Endpoint: /custom-metrics")
    print(f"📝 Custom Logs Endpoint: /custom-logs") 
    print(f"🔗 Custom Traces Endpoint: /custom-traces")
    print(f"🔗 OTLP HTTP Metrics: /v1/metrics")
    print(f"🔗 OTLP Logs: /v1/logs")
    print("✨ Now handling ALL telemetry: metrics, logs, AND traces!")
    print("🎯 Will show Kubernetes events, pod logs, distributed traces, and all telemetry data")
    print("🗜️ GZIP/DEFLATE compression support enabled")
    print("🔑 Custom headers support with masked authorization tokens")
    print("📋 OTLP-like hierarchical structure support")
    print("🎨 Enhanced resource group visualization")
    print("🔗 Advanced trace analysis with service maps, error tracking, and performance metrics\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

if __name__ == '__main__':
    main()