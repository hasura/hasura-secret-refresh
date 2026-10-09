FROM us-docker.pkg.dev/hasura-container-images/external-images/docker.io/library/golang:1.25-alpine-stable AS builder

# Honour the go.mod `toolchain` directive so the binary is compiled with the
# pinned Go toolchain (go1.26.9) even though the builder base ships an older
# 1.25.x compiler. go1.26.9 carries the stdlib fixes for CVE-2026-78667 and
# CVE-2026-97031. GOTOOLCHAIN=auto is the Go default; set explicitly so the
# fix does not silently regress if the base image ever pins GOTOOLCHAIN=local.
ENV GOTOOLCHAIN=auto

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o secrets-management-proxy

FROM us-docker.pkg.dev/hasura-container-images/external-images/docker.io/library/alpine:3.23-stable

# Install CA certificates and require an OpenSSL build containing the security
# fixes shipped in Alpine's 3.5.8-r0 packages. Keep the lower bound so a newer
# security revision remains installable as the repository advances.
RUN apk --no-cache add \
    ca-certificates \
    'libcrypto3>=3.5.8-r0' \
    'libssl3>=3.5.8-r0'

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
