package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

// Metrics service implementation
type metricsService struct {
	pmetricotlp.UnimplementedGRPCServer
}

func (s *metricsService) Export(ctx context.Context, req pmetricotlp.ExportRequest) (pmetricotlp.ExportResponse, error) {
	log.Printf("\n=== ARROW METRICS RECEIVED ===")
	log.Printf("Time: %s", time.Now().Format(time.RFC3339))
	
	metrics := req.Metrics()
	log.Printf("dump metrics: %+v", metrics)
	log.Printf("Resource Metrics Count: %d", metrics.ResourceMetrics().Len())
	
	// Show first few resource metrics
	for i := 0; i < metrics.ResourceMetrics().Len() && i < 3; i++ {
		rm := metrics.ResourceMetrics().At(i)
		
		log.Printf("\nResource %d:", i+1)
		
		// Show resource attributes
		attrs := rm.Resource().Attributes()
		log.Printf("   Attributes (%d):", attrs.Len())
		
		attrs.Range(func(k string, v pcommon.Value) bool {
			if k == "k8s.namespace.name" || k == "k8s.pod.name" || k == "k8s.container.name" {
				log.Printf("      %s: %s", k, v.AsString())
			}
			return true
		})
		
		// Show scope metrics
		for j := 0; j < rm.ScopeMetrics().Len() && j < 2; j++ {
			sm := rm.ScopeMetrics().At(j)
			log.Printf("   Scope %d: %d metrics", j+1, sm.Metrics().Len())
			
			// Show first few metrics
			for k := 0; k < sm.Metrics().Len() && k < 3; k++ {
				metric := sm.Metrics().At(k)
				log.Printf("      - %s (%s)", metric.Name(), metric.Type().String())
			}
		}
	}
	
	// Convert to JSON for detailed inspection
	jsonMarshaler := &pmetric.JSONMarshaler{}
	jsonData, err := jsonMarshaler.MarshalMetrics(metrics)
	if err != nil {
		log.Printf("Error converting to JSON: %v", err)
	} else {
		log.Printf("\nJSON Size: %d bytes", len(jsonData))
		
		// Show first 500 chars of JSON
		if len(jsonData) > 500 {
			log.Printf("JSON Preview: %s...", string(jsonData[:500]))
		} else {
			log.Printf("Full JSON: %s", string(jsonData))
		}
	}
	
	log.Printf("=====================================\n")
	
	return pmetricotlp.NewExportResponse(), nil
}

// Logs service implementation  
type logsService struct {
	plogotlp.UnimplementedGRPCServer
}

func (s *logsService) Export(ctx context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	log.Printf("\n=== ARROW LOGS RECEIVED ===")
	log.Printf("Time: %s", time.Now().Format(time.RFC3339))
	
	logs := req.Logs()
	log.Printf("Resource Logs Count: %d", logs.ResourceLogs().Len())
	
	// Convert to JSON
	jsonMarshaler := &plog.JSONMarshaler{}
	jsonData, err := jsonMarshaler.MarshalLogs(logs)
	if err != nil {
		log.Printf("Error converting logs to JSON: %v", err)
	} else {
		log.Printf("Logs JSON Size: %d bytes", len(jsonData))
		
		if len(jsonData) > 300 {
			log.Printf("Logs JSON Preview: %s...", string(jsonData[:300]))
		} else {
			log.Printf("Full Logs JSON: %s", string(jsonData))
		}
	}
	
	log.Printf("=====================================\n")
	
	return plogotlp.NewExportResponse(), nil
}

func main() {
	// Create gRPC server
	lis, err := net.Listen("tcp", ":4317")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()

	// Register services
	pmetricotlp.RegisterGRPCServer(s, &metricsService{})
	plogotlp.RegisterGRPCServer(s, &logsService{})

	log.Printf("gRPC Arrow Debug Server starting on :4317")
	log.Printf("Ready to receive Apache Arrow formatted OTLP data")
	log.Printf("Will show structure and convert to JSON for inspection")

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

