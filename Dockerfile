FROM us-docker.pkg.dev/hasura-container-images/external-images/docker.io/library/golang:1.25-alpine-stable AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o secrets-management-proxy

FROM us-docker.pkg.dev/hasura-container-images/external-images/docker.io/library/alpine:3.23-stable

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# TODO: Remove this targeted upgrade once the alpine:3.23-stable base snapshot
# ships openssl libcrypto3/libssl3 >= 3.5.7-r0. The snapshot currently lags at
# 3.5.6-r0, which is vulnerable to CVE-2026-45447 (HIGH, heap use-after-free in
# PKCS7_verify) and trips the trivy HIGH/CRITICAL gate. Bump just the affected
# libs until the base picks up the fix automatically.
RUN apk --no-cache upgrade libcrypto3 libssl3

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/secrets-management-proxy /app/secrets-management-proxy

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

CMD ["/app/secrets-management-proxy", "--bind-addr=127.0.0.1:5353"]
