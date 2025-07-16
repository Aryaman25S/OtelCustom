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
            
            actual_metrics = data.get('actual_metrics', [])
            print(f"\n📈 SAMPLE METRICS ({len(actual_metrics)} total):")
            print("=" * 80)
            
            # Show first 5 metrics as examples
            for i, metric in enumerate(actual_metrics[:5]):
                print(f"\nMetric {i+1}: {metric.get('name', 'N/A')}")
                print(f"  Type: {metric.get('type', 'N/A')}")
                print(f"  Unit: '{metric.get('unit', '')}'" + (" (no unit)" if not metric.get('unit') else ""))
                
                data_points = metric.get('data_points', [])
                if data_points:
                    point = data_points[0]
                    value = point.get('value', 'N/A')
                    if isinstance(value, (int, float)):
                        print(f"  Current Value: {value} {metric.get('unit', '')}")
                    
                    resource = metric.get('resource', {})
                    if 'k8s.pod.name' in resource:
                        print(f"  Pod: {resource.get('k8s.pod.name')}")
                    elif 'k8s.node.name' in resource:
                        print(f"  Node: {resource.get('k8s.node.name')}")
                        
            if len(actual_metrics) > 5:
                print(f"\n... and {len(actual_metrics) - 5} more metrics")
            
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
            
            actual_logs = data.get('actual_logs', [])
            print(f"\n📋 ALL KUBERNETES LOGS ({len(actual_logs)} total):")
            print("=" * 100)
            
            # Group logs by severity
            log_levels = {}
            for log in actual_logs:
                severity = log.get('severity_text', 'UNKNOWN')
                if severity not in log_levels:
                    log_levels[severity] = []
                log_levels[severity].append(log)
            
            print(f"\n📊 LOG LEVEL BREAKDOWN:")
            for level, logs in sorted(log_levels.items()):
                print(f"  {level}: {len(logs)} logs")
            
            print(f"\n📋 RECENT LOG ENTRIES:")
            print("-" * 100)
            
            for i, log in enumerate(actual_logs):
                # Convert timestamp
                timestamp = log.get('timestamp', 0)
                if timestamp and timestamp > 0:
                    if timestamp > 1e15:  # nanoseconds
                        timestamp /= 1e9
                    log_time = datetime.fromtimestamp(timestamp)
                else:
                    log_time = "Unknown time"
                
                # Extract log details
                severity = log.get('severity_text', 'INFO')
                body = log.get('body', 'No message')
                resource = log.get('resource', {})
                
                # Format resource info
                resource_info = []
                if 'k8s.pod.name' in resource:
                    resource_info.append(f"Pod: {resource['k8s.pod.name']}")
                if 'k8s.namespace.name' in resource:
                    resource_info.append(f"NS: {resource['k8s.namespace.name']}")
                if 'k8s.node.name' in resource:
                    resource_info.append(f"Node: {resource['k8s.node.name']}")
                
                resource_str = " | ".join(resource_info) if resource_info else "Unknown resource"
                
                print(f"\nLog {i+1}: [{severity}] {log_time}")
                print(f"  Resource: {resource_str}")
                print(f"  Message: {body}")
                
                # Show attributes if present
                attributes = log.get('attributes', {})
                if attributes:
                    attr_str = ", ".join([f"{k}:{v}" for k, v in attributes.items() if k.startswith('k8s.')])
                    if attr_str:
                        print(f"  K8s Attributes: {attr_str}")
                
                # Show trace information if present
                trace_id = log.get('trace_id', '')
                span_id = log.get('span_id', '')
                if trace_id and trace_id != '00000000000000000000000000000000':
                    print(f"  Trace ID: {trace_id}")
                if span_id and span_id != '0000000000000000':
                    print(f"  Span ID: {span_id}")
                
                print("-" * 100)
                
                # Limit to first 10 logs for readability
                if i >= 9:
                    remaining = len(actual_logs) - 10
                    if remaining > 0:
                        print(f"\n... and {remaining} more log entries")
                    break
            
            print(f"\n📈 LOG STATISTICS:")
            severity_counts = {}
            namespaces = set()
            pods = set()
            
            for log in actual_logs:
                severity = log.get('severity_text', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                resource = log.get('resource', {})
                if 'k8s.namespace.name' in resource:
                    namespaces.add(resource['k8s.namespace.name'])
                if 'k8s.pod.name' in resource:
                    pods.add(resource['k8s.pod.name'])
            
            print(f"  Severity Distribution: {severity_counts}")
            print(f"  Unique Namespaces: {len(namespaces)} ({list(namespaces)})")
            print(f"  Unique Pods: {len(pods)}")
            
        except Exception as e:
            print(f"Error parsing logs data: {e}")
            print(f"Raw body size: {len(raw_body)} bytes")
            if len(raw_body) < 1000:
                print(f"Raw body: {raw_body}")
        
        print("\n=== END LOGS ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "success", "source": "logs_handler", "logs_processed": len(actual_logs) if 'actual_logs' in locals() else 0}
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
            
            actual_traces = data.get('actual_traces', [])
            print(f"\n🔗 ALL DISTRIBUTED TRACES ({len(actual_traces)} spans total):")
            print("=" * 100)
            
            # Group traces by trace ID
            trace_groups = {}
            for span in actual_traces:
                trace_id = span.get('trace_id', 'unknown')
                if trace_id not in trace_groups:
                    trace_groups[trace_id] = []
                trace_groups[trace_id].append(span)
            
            print(f"\n📊 TRACE SUMMARY:")
            print(f"  Total Unique Traces: {len(trace_groups)}")
            print(f"  Total Spans: {len(actual_traces)}")
            print(f"  Average Spans per Trace: {len(actual_traces) / len(trace_groups) if trace_groups else 0:.1f}")
            
            # Show trace breakdown by service
            services = {}
            for span in actual_traces:
                service_name = span.get('resource', {}).get('service.name', 'unknown-service')
                if service_name not in services:
                    services[service_name] = 0
                services[service_name] += 1
            
            print(f"  Services: {len(services)}")
            for service, count in sorted(services.items()):
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
                sorted_spans = sorted(spans, key=lambda s: s.get('start_time', 0))
                
                for i, span in enumerate(sorted_spans):
                    # Calculate duration
                    duration_ns = span.get('duration_ns', 0)
                    duration_ms = duration_ns / 1_000_000 if duration_ns else 0
                    
                    # Extract key attributes
                    resource = span.get('resource', {})
                    attributes = span.get('attributes', {})
                    
                    # Format span info
                    service_name = resource.get('service.name', 'unknown-service')
                    operation_name = span.get('name', 'unknown-operation')
                    status = span.get('status_code', 'UNSET')
                    
                    # Show indentation for child spans
                    indent = "    " if span.get('parent_span_id', '0000000000000000') != '0000000000000000' else "  "
                    
                    print(f"{indent}Span {i+1}: {operation_name}")
                    print(f"{indent}  Service: {service_name}")
                    print(f"{indent}  Kind: {span.get('kind', 'INTERNAL')}")
                    print(f"{indent}  Duration: {duration_ms:.2f}ms")
                    print(f"{indent}  Status: {status}")
                    
                    if span.get('status_message'):
                        print(f"{indent}  Message: {span.get('status_message')}")
                    
                    # Show key attributes
                    key_attrs = {k: v for k, v in attributes.items() 
                               if k in ['http.method', 'http.url', 'http.status_code', 'db.statement', 'error']}
                    if key_attrs:
                        attr_str = ", ".join([f"{k}={v}" for k, v in key_attrs.items()])
                        print(f"{indent}  Attributes: {attr_str}")
                    
                    # Show events if any
                    events = span.get('events', [])
                    if events:
                        print(f"{indent}  Events: {len(events)} events")
                        for event in events[:2]:  # Show first 2 events
                            print(f"{indent}    - {event.get('name', 'unnamed-event')}")
                
                print("-" * 100)
            
            if len(trace_groups) > 3:
                remaining = len(trace_groups) - 3
                print(f"\n... and {remaining} more traces")
            
            print(f"\n📈 TRACE STATISTICS:")
            
            # Status distribution
            status_counts = {}
            error_count = 0
            total_duration = 0
            
            for span in actual_traces:
                status = span.get('status_code', 'UNSET')
                status_counts[status] = status_counts.get(status, 0) + 1
                
                if status == 'ERROR':
                    error_count += 1
                
                duration = span.get('duration_ns', 0)
                total_duration += duration
            
            print(f"  Status Distribution: {status_counts}")
            print(f"  Error Rate: {(error_count / len(actual_traces) * 100):.1f}%" if actual_traces else "0%")
            print(f"  Average Span Duration: {(total_duration / len(actual_traces) / 1_000_000):.2f}ms" if actual_traces else "0ms")
            
            # Unique namespaces and pods from traces
            namespaces = set()
            pods = set()
            
            for span in actual_traces:
                resource = span.get('resource', {})
                if 'k8s.namespace.name' in resource:
                    namespaces.add(resource['k8s.namespace.name'])
                if 'k8s.pod.name' in resource:
                    pods.add(resource['k8s.pod.name'])
            
            print(f"  Unique Namespaces: {len(namespaces)} ({list(namespaces)})")
            print(f"  Unique Pods: {len(pods)}")
            
        except Exception as e:
            print(f"Error parsing traces data: {e}")
            print(f"Raw body size: {len(raw_body)} bytes")
            if len(raw_body) < 1000:
                print(f"Raw body: {raw_body}")
        
        print("\n=== END TRACES ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "success", "source": "traces_handler", "spans_processed": len(actual_traces) if 'actual_traces' in locals() else 0}
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
    print("🔑 Custom headers support with masked authorization tokens\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

if __name__ == '__main__':
    main()