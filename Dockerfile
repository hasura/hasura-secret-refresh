FROM us-docker.pkg.dev/hasura-container-images/external-images/docker.io/library/golang:1.25-alpine-stable AS builder

# Compile with Go 1.26.9 even though this -stable builder base ships an older
# 1.25.x compiler and pins GOTOOLCHAIN=local (under which a go.mod `toolchain`
# line is silently ignored). Pin GOTOOLCHAIN to the exact fixed toolchain so
# the builder fetches and uses go1.26.9, which carries the stdlib fixes for
# CVE-2026-78667 and CVE-2026-97031. This also satisfies the go.mod `go 1.26.0`
# requirement introduced by golang.org/x/net v0.60.0 (CVE-2026-78669).
ENV GOTOOLCHAIN=go1.26.9

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
