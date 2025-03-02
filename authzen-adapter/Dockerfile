# --------------------------------------------------------
# Stage 1: Build the Go application
# --------------------------------------------------------
    FROM golang:1.23-alpine AS builder

    # Set the working directory inside the container
    WORKDIR /app
    
    # Copy the Go modules files and download dependencies
    COPY go.mod go.sum ./
    RUN go mod download
    
    # Copy the rest of the application source code
    COPY . .
        
    # Build the Go application
    RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /authzen-pdp .
    
    # --------------------------------------------------------
    # Stage 2: Create a minimal image with the compiled Go binary
    # --------------------------------------------------------
    FROM alpine:latest
    
    # Optionally, create a non-root user
    # RUN addgroup -S appgroup && adduser -S appuser -G appgroup
    # USER appuser
    
    WORKDIR /root/
    
    # Copy the binary from the builder stage
    COPY --from=builder /authzen-pdp .
    
    # Copy the env file (assuming it’s safe to include in the final image)
    COPY .env .env
    
    # Expose the application's port
    EXPOSE 8080
    
    # Set the entrypoint to the Go application binary
    ENTRYPOINT ["./authzen-pdp"]