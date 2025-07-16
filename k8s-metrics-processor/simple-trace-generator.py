#!/usr/bin/env python3

import json
import requests
import time
import random
from datetime import datetime

def generate_trace_id():
    """Generate a random 32-character hex trace ID"""
    return ''.join([f'{random.randint(0, 15):x}' for _ in range(32)])

def generate_span_id():
    """Generate a random 16-character hex span ID"""
    return ''.join([f'{random.randint(0, 15):x}' for _ in range(16)])

def create_test_trace():
    """Create a test trace with multiple spans"""
    trace_id = generate_trace_id()
    current_time_ns = int(time.time() * 1_000_000_000)
    
    # Create a parent span (web request)
    parent_span_id = generate_span_id()
    parent_span = {
        "traceId": trace_id,
        "spanId": parent_span_id,
        "name": "GET /api/users",
        "kind": 2,  # SERVER
        "startTimeUnixNano": str(current_time_ns),
        "endTimeUnixNano": str(current_time_ns + 250_000_000),  # 250ms
        "attributes": [
            {"key": "http.method", "value": {"stringValue": "GET"}},
            {"key": "http.url", "value": {"stringValue": "/api/users"}},
            {"key": "http.status_code", "value": {"intValue": "200"}},
            {"key": "user.id", "value": {"stringValue": "12345"}}
        ],
        "status": {"code": 1}  # OK
    }
    
    # Create a child span (database query)
    child_span_id = generate_span_id()
    child_span = {
        "traceId": trace_id,
        "spanId": child_span_id,
        "parentSpanId": parent_span_id,
        "name": "SELECT users",
        "kind": 3,  # CLIENT
        "startTimeUnixNano": str(current_time_ns + 50_000_000),  # 50ms after parent
        "endTimeUnixNano": str(current_time_ns + 200_000_000),   # 150ms duration
        "attributes": [
            {"key": "db.system", "value": {"stringValue": "postgresql"}},
            {"key": "db.statement", "value": {"stringValue": "SELECT * FROM users WHERE active = true"}},
            {"key": "db.name", "value": {"stringValue": "app_db"}}
        ],
        "status": {"code": 1}  # OK
    }
    
    # Create the complete trace payload
    trace_payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "user-service"}},
                        {"key": "service.version", "value": {"stringValue": "1.2.3"}},
                        {"key": "k8s.namespace.name", "value": {"stringValue": "production"}},
                        {"key": "k8s.pod.name", "value": {"stringValue": "user-service-abc123"}},
                        {"key": "k8s.deployment.name", "value": {"stringValue": "user-service"}},
                        {"key": "environment", "value": {"stringValue": "production"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "user-service-tracer",
                            "version": "1.0.0"
                        },
                        "spans": [parent_span, child_span]
                    }
                ]
            }
        ]
    }
    
    return trace_payload

def send_trace_to_collector(trace_payload, endpoint="http://localhost:4318/v1/traces"):
    """Send trace to OpenTelemetry collector"""
    try:
        response = requests.post(
            endpoint,
            json=trace_payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TraceGenerator/1.0"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"✅ Trace sent successfully to {endpoint}")
            return True
        else:
            print(f"❌ Failed to send trace: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error sending trace: {e}")
        return False

def generate_error_trace():
    """Generate a trace with an error span"""
    trace_id = generate_trace_id()
    current_time_ns = int(time.time() * 1_000_000_000)
    
    error_span = {
        "traceId": trace_id,
        "spanId": generate_span_id(),
        "name": "POST /api/orders",
        "kind": 2,  # SERVER
        "startTimeUnixNano": str(current_time_ns),
        "endTimeUnixNano": str(current_time_ns + 500_000_000),  # 500ms
        "attributes": [
            {"key": "http.method", "value": {"stringValue": "POST"}},
            {"key": "http.url", "value": {"stringValue": "/api/orders"}},
            {"key": "http.status_code", "value": {"intValue": "500"}},
            {"key": "error", "value": {"boolValue": True}},
            {"key": "error.message", "value": {"stringValue": "Database connection timeout"}}
        ],
        "status": {
            "code": 2,  # ERROR
            "message": "Internal server error: Database connection timeout"
        },
        "events": [
            {
                "name": "exception",
                "timeUnixNano": str(current_time_ns + 300_000_000),
                "attributes": [
                    {"key": "exception.type", "value": {"stringValue": "DatabaseTimeoutError"}},
                    {"key": "exception.message", "value": {"stringValue": "Connection timeout after 5 seconds"}}
                ]
            }
        ]
    }
    
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "order-service"}},
                        {"key": "service.version", "value": {"stringValue": "2.1.0"}},
                        {"key": "k8s.namespace.name", "value": {"stringValue": "production"}},
                        {"key": "k8s.pod.name", "value": {"stringValue": "order-service-xyz789"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "order-service-tracer"},
                        "spans": [error_span]
                    }
                ]
            }
        ]
    }

def main():
    print("🔗 OpenTelemetry Trace Generator v1.0")
    print("=====================================")
    
    # Try to send to your collector (adjust the endpoint as needed)
    endpoints = [
        "http://localhost:4318/v1/traces",  # If port-forwarding
        "http://host.docker.internal:4318/v1/traces"  # If running in Docker
    ]
    
    success_count = 0
    
    for i in range(5):
        print(f"\n📊 Generating trace {i+1}/5...")
        
        if i == 3:  # Make one error trace
            trace = generate_error_trace()
            print("   🚨 Creating ERROR trace with exception")
        else:
            trace = create_test_trace()
            print("   ✅ Creating SUCCESS trace")
        
        # Try different endpoints
        sent = False
        for endpoint in endpoints:
            if send_trace_to_collector(trace, endpoint):
                success_count += 1
                sent = True
                break
        
        if not sent:
            print(f"   ❌ Failed to send trace {i+1}")
        
        # Wait a bit between traces
        time.sleep(2)
    
    print(f"\n📈 Summary: {success_count}/5 traces sent successfully")
    print("\n🔍 Check your debug server console for trace output!")
    print("💡 If no traces appear, make sure your collector is running and accessible")

if __name__ == "__main__":
    main()