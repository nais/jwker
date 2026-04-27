FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ENV CGO_ENABLED=0
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o bin/jwker ./cmd/jwker

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /src/bin/jwker /app/jwker
ENTRYPOINT ["/app/jwker"]
