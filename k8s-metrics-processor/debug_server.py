#!/usr/bin/env python3

import gzip
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class RawDebugHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print(f"\n--- REQUEST at {datetime.now()} ---")
        print(f"Path: {self.path}")
        print(f"Headers: {dict(self.headers)}")
        
        # Read raw body
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        
        print(f"Body size: {len(raw_body)} bytes")
        print(f"Raw body (first 50 hex): {raw_body[:50].hex()}")
        
        # Check if gzipped and decompress
        if len(raw_body) >= 2 and raw_body[0] == 0x1f and raw_body[1] == 0x8b:
            print("Data is GZIPPED - decompressing...")
            try:
                decompressed = gzip.decompress(raw_body)
                print(f"Decompressed size: {len(decompressed)} bytes")
                
                # Try as text
                try:
                    text_content = decompressed.decode('utf-8')
                    print(f"Decompressed content: {text_content}")
                except:
                    print("Cannot decode decompressed data as UTF-8")
                    print(f"Decompressed bytes: {decompressed}")
                    
            except Exception as e:
                print(f"Failed to decompress: {e}")
        else:
            print("Data is NOT gzipped")
            # Try as text
            try:
                print(f"As text: {raw_body.decode('utf-8')}")
            except:
                print("Cannot decode as UTF-8")
                print(f"Raw body (bytes): {raw_body}")
        
        print("--- END ---\n")
        
        # Send OK response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    server = HTTPServer(('', 8080), RawDebugHandler)
    print("Raw debug server with GZIP handling listening on :8080")
    server.serve_forever()
