FROM golang:1.21.0-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o secrets-management-proxy

FROM alpine:3.18.3

COPY --from=builder /app/secrets-management-proxy /secrets-management-proxy

RUN chmod +x /secrets-management-proxy

EXPOSE 5353

CMD ["/secrets-management-proxy"]
