FROM golang:1.25.1-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
COPY *.go ./
COPY testdata/ ./testdata/

RUN CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  go vet ./... && \
  go test ./... && \
  go build -o /creamy-waha

# for the CA certs
FROM alpine
COPY --from=builder /creamy-waha /creamy-waha
ENTRYPOINT ["/creamy-waha"]
