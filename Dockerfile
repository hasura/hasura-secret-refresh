FROM golang:1.21.0-alpine

WORKDIR /app

COPY . .

RUN go build -o hasura-secret-refresh

EXPOSE 8080

CMD ["./hasura-secret-refresh"]
