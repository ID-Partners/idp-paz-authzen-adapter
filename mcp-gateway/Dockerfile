# Stage 1: build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /mcp-authzen-gateway .

# Stage 2: minimal runtime
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /root
COPY --from=builder /mcp-authzen-gateway .
EXPOSE 8080
ENTRYPOINT ["./mcp-authzen-gateway"]
