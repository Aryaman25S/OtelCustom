import grpc
from concurrent import futures
from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2, metrics_service_pb2_grpc

class MetricsServicer(metrics_service_pb2_grpc.MetricsServiceServicer):
    def Export(self, request, context):
        print("\n=== RAW REQUEST RECEIVED ===")
        print(request)
        print("============================\n")
        return metrics_service_pb2.ExportMetricsServiceResponse()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    metrics_service_pb2_grpc.add_MetricsServiceServicer_to_server(MetricsServicer(), server)
    server.add_insecure_port('[::]:4317')
    server.start()
    print("gRPC server listening on port 4317...")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
