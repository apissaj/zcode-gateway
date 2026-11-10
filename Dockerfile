# zcode-gateway — multi-stage build (upstream ships no Dockerfile)
#
# The Go module pins a toolchain newer than any published base tag, so the
# build stage lets Go fetch the right one (GOTOOLCHAIN=auto).
#
#   docker build -t zcode-gateway:local .
#   docker compose -f docker-compose.example.yml up -d
FROM golang:alpine AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zcode-gateway ./cmd/zcode-gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/zcode-gateway /app/zcode-gateway

# HOST must be 0.0.0.0 inside a container: the binary defaults to 127.0.0.1,
# which a published port cannot reach.
ENV HOST=0.0.0.0 \
    PORT=20131 \
    ZCODE_STATE_DIR=/app/data \
    ZCODE_ACCOUNTS_FILE=/app/data/accounts.json \
    ZCODE_PLAN_JWT_FILE=/app/data/plan-jwt.json \
    ZCODE_DEFAULT_EFFORT=low

EXPOSE 20131
VOLUME ["/app/data"]
ENTRYPOINT ["/app/zcode-gateway"]
