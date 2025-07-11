#!/usr/bin/env python3

import gzip
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class FullMetricsDebugHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path.startswith('/custom-metrics'):
            self.handle_custom_exporter()
        elif self.path.startswith('/v1/metrics'):
            self.handle_otlp_metrics()
        elif self.path.startswith('/v1/logs'):
            self.handle_otlp_logs()
        else:
            self.handle_unknown()

    def handle_custom_exporter(self):
        print(f"\n=== ENHANCED CUSTOM GO EXPORTER at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        print(f"Headers:")
        for header, value in self.headers.items():
            print(f"  {header}: {value}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        try:
            data = json.loads(raw_body.decode('utf-8'))
            print(f"\nENHANCED CUSTOM EXPORTER DATA:")
            print(f"  Source: {data.get('source', 'unknown')}")
            print(f"  Timestamp: {datetime.fromtimestamp(data.get('timestamp', 0))}")
            print(f"  Metric Count: {data.get('metric_count', 0)}")
            print(f"  Resource Count: {data.get('resource_count', 0)}")
            print(f"  Payload Size: {len(raw_body)} bytes")
            print(f"  Custom Field: {data.get('custom_field', 'N/A')}")
            
            k8s_data = data.get('kubernetes_summary', {})
            print(f"  Kubernetes Summary:")
            print(f"    Nodes: {k8s_data.get('nodes', [])}")
            print(f"    Namespaces: {k8s_data.get('namespaces', [])}")
            print(f"    Pods: {len(k8s_data.get('pods', []))} pods")
            print(f"    Deployments: {len(k8s_data.get('deployments', []))} deployments")
            print(f"    Services: {len(k8s_data.get('services', []))} services")
            
            actual_metrics = data.get('actual_metrics', [])
            print(f"\nALL ACTUAL METRICS DATA ({len(actual_metrics)} total):")
            print("=" * 80)
            
            for i, metric in enumerate(actual_metrics):
                print(f"\nMetric {i+1}:")
                print(f"    Name: {metric.get('name', 'N/A')}")
                print(f"    Type: {metric.get('type', 'N/A')}")
                print(f"    Unit: '{metric.get('unit', '')}'" + (" (no unit)" if not metric.get('unit') else ""))
                print(f"    Description: {metric.get('description', 'N/A')}")
                
                resource = metric.get('resource', {})
                if 'k8s.pod.name' in resource:
                    print(f"    Pod: {resource.get('k8s.pod.name')}")
                    print(f"    Namespace: {resource.get('k8s.namespace.name', 'N/A')}")
                    print(f"    Node: {resource.get('k8s.node.name', 'N/A')}")
                elif 'k8s.node.name' in resource:
                    print(f"    Node: {resource.get('k8s.node.name')}")
                elif 'k8s.deployment.name' in resource:
                    print(f"    Deployment: {resource.get('k8s.deployment.name')}")
                    print(f"    Namespace: {resource.get('k8s.namespace.name', 'N/A')}")
                else:
                    resource_info = [f"{k}: {v}" for k, v in resource.items() if k.startswith('k8s.')]
                    if resource_info:
                        print(f"    Resource: {', '.join(resource_info[:3])}")
                
                scope = metric.get('scope', {})
                if scope.get('name'):
                    print(f"    Scope: {scope.get('name', '')} v{scope.get('version', 'unknown')}")
                
                data_points = metric.get('data_points', [])
                print(f"    Data Points: {len(data_points)}")
                
                for j, point in enumerate(data_points):
                    print(f"      Point {j+1}:")
                    value = point.get('value', 'N/A')
                    if isinstance(value, (int, float)):
                        if metric.get('unit'):
                            print(f"        VALUE: {value} {metric.get('unit')}")
                        else:
                            print(f"        VALUE: {value}")
                    else:
                        print(f"        VALUE: {value}")
                    
                    if 'timestamp' in point:
                        ts = point['timestamp']
                        if ts and ts > 0:
                            if ts > 1e15:
                                ts /= 1e9
                            print(f"        Timestamp: {datetime.fromtimestamp(ts)}")
                    
                    if 'start_timestamp' in point:
                        start_ts = point['start_timestamp']
                        if start_ts and start_ts > 0:
                            if start_ts > 1e15:
                                start_ts /= 1e9
                            print(f"        Start Time: {datetime.fromtimestamp(start_ts)}")
                    
                    if 'is_monotonic' in point:
                        print(f"        Monotonic: {point['is_monotonic']}")
                    if 'aggregation_temporality' in point:
                        print(f"        Temporality: {point['aggregation_temporality']}")
                    
                    attributes = point.get('attributes', {})
                    if attributes:
                        print(f"        Attributes: {attributes}")
                    
                    if 'count' in point:
                        print(f"        Count: {point['count']}")
                    if 'sum' in point:
                        print(f"        Sum: {point['sum']}")
                    if 'bucket_counts' in point:
                        print(f"        Bucket Counts: {point['bucket_counts']}")
                    if 'quantiles' in point:
                        print(f"        Quantiles: {point['quantiles']}")
                
                if i < len(actual_metrics) - 1:
                    print("-" * 60)
            
            print("\n" + "=" * 80)
            
            metric_types = {}
            metric_names = {}
            for metric in actual_metrics:
                metric_type = metric.get('type', 'Unknown')
                metric_types[metric_type] = metric_types.get(metric_type, 0) + 1
                
                name = metric.get('name', 'Unknown')
                metric_names[name] = metric_names.get(name, 0) + 1
            
            print(f"\nFINAL STATISTICS:")
            print(f"METRIC TYPE BREAKDOWN:")
            for metric_type, count in sorted(metric_types.items()):
                print(f"    {metric_type}: {count} metrics")
            
            print(f"\nALL METRIC NAMES AND FREQUENCIES:")
            sorted_names = sorted(metric_names.items(), key=lambda x: x[1], reverse=True)
            for name, count in sorted_names:
                print(f"    {name}: {count} instances")
            
        except Exception as e:
            print(f"Error parsing enhanced custom exporter data: {e}")
            print(f"Raw body size: {len(raw_body)} bytes")
            if len(raw_body) < 1000:
                print(f"Raw body: {raw_body}")
            else:
                print(f"Raw body (first 500 chars): {raw_body[:500]}...")
        
        print("\n=== END ENHANCED CUSTOM EXPORTER ===\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "success", "source": "full_metrics_handler", "metrics_processed": len(actual_metrics)}
        self.wfile.write(json.dumps(response).encode())

    def handle_otlp_metrics(self):
        print(f"\n=== OTLP HTTP METRICS at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        print(f"Body size: {len(raw_body)} bytes")
        
        if self.headers.get('Content-Encoding') == 'gzip' or (len(raw_body) >= 2 and raw_body[0] == 0x1f and raw_body[1] == 0x8b):
            print("Data is GZIPPED - decompressing...")
            try:
                body = gzip.decompress(raw_body)
                print(f"Decompressed size: {len(body)} bytes")
            except Exception as e:
                print(f"Failed to decompress: {e}")
                body = raw_body
        else:
            print("Data is NOT compressed")
            body = raw_body
        
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
    server = HTTPServer(('', port), FullMetricsDebugHandler)
    print(f"FULL METRICS Debug Server v3.0 listening on port {port}")
    print(f"OTLP HTTP Endpoint: /v1/metrics (raw OpenTelemetry data)")
    print(f"Custom Exporter Endpoint: /custom-metrics (ALL 162 metrics shown!)")
    print(f"OTLP Logs Endpoint: /v1/logs")
    print("WARNING: Will show ALL metrics - output will be very long!")
    print("TIP: Pipe to a file if needed: python3 debug_server_new.py > metrics.log 2>&1\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

if __name__ == '__main__':
    main()
