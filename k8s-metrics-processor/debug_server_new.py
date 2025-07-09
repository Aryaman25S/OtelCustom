#!/usr/bin/env python3

import gzip
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class OTLPDebugHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print(f"\n=== REQUEST at {datetime.now()} ===")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        print(f"Headers:")
        for header, value in self.headers.items():
            print(f"  {header}: {value}")
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        print(f"\nBody size: {len(raw_body)} bytes")
        
        # Handle gzip compression if present
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
        
        # Try to decode as text
        try:
            text_content = body.decode('utf-8')
            print(f"\nFull Content:")
            print(text_content)
                
            # Try to parse as JSON and show structure
            if text_content.strip().startswith('{'):
                try:
                    data = json.loads(text_content)
                    print(f"\nJSON Structure Summary:")
                    if isinstance(data, dict):
                        print(f"Top-level keys: {list(data.keys())}")
                        
                        # Show OTLP structure if present
                        if 'resourceMetrics' in data:
                            metrics = data['resourceMetrics']
                            print(f"Resource metrics count: {len(metrics)}")
                            
                        if 'resourceLogs' in data:
                            logs = data['resourceLogs']
                            print(f"Resource logs count: {len(logs)}")
                            
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON: {e}")
            else:
                print("Content does not appear to be JSON")
                
        except UnicodeDecodeError:
            print(f"\nBinary data - cannot decode as text")
            print(f"Raw bytes (first 100): {raw_body[:100]}")
        
        print("=== END ===\n")
        
        # Send successful response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, format, *args):
        # Suppress default HTTP server logging
        pass

def main():
    port = 8080
    server = HTTPServer(('', port), OTLPDebugHandler)
    print(f"OTLP HTTP Debug Server listening on port {port}")
    print(f"Endpoints: /v1/metrics, /v1/logs")
    print("Will print all received OTLP data\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

if __name__ == '__main__':
    main()