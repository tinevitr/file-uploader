FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/public ./public


RUN mkdir -p uploads

EXPOSE 7860

ENV PORT=7860
ENV API_KEY=default-dev-key-change-me

CMD ["./main"]
