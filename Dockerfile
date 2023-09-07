FROM golang:1.21.0-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o hasura-secret-refresh

FROM alpine:3.18.3

COPY --from=builder /app/hasura-secret-refresh /hasura-secret-refresh

RUN chmod +x /hasura-secret-refresh

EXPOSE 5353

CMD ["/hasura-secret-refresh"]
