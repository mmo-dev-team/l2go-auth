# Build stage
FROM golang:1.25.1-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o l2go-auth cmd/main.go

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/l2go-auth .

# Expose ports
# Client Listener
EXPOSE 2106
# Game Server Listener
EXPOSE 9014
# Prometheus Metrics
EXPOSE 9090

# Command to run the application
CMD ["./l2go-auth"]
