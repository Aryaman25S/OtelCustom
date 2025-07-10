# Dockerfile - save as k8s-metrics-processor/Dockerfile
FROM alpine:3.18

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 10001 otel && \
    adduser -D -u 10001 -G otel otel

# Copy the custom collector binary
COPY custom-collector/custom-otelcol /otelcol

# Set ownership and permissions
RUN chown otel:otel /otelcol && \
    chmod 755 /otelcol

# Switch to non-root user
USER otel

# Expose common OTLP ports
EXPOSE 4317 4318 8888 8889 13133

# Set entrypoint - matches your existing otel-ds.yaml args
ENTRYPOINT ["/otelcol"]
CMD ["--config=/conf/relay.yaml"]
