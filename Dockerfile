# Gunakan multi-stage build untuk mengurangi ukuran image
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy dependency files terlebih dahulu untuk memanfaatkan cache
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build aplikasi
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Stage final
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary dari builder
COPY --from=builder /app/main .

# Buat direktori uploads
RUN mkdir -p uploads

# Expose port
EXPOSE 7860

# Environment variables
ENV PORT=7860
ENV API_KEY=default-dev-key-change-me

# Run aplikasi
CMD ["go", "run", "main.go"]
