# Build the manager binary
FROM golang:1.24 AS builder

COPY . /workspace
WORKDIR /workspace

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download
# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -installsuffix cgo -o jwker cmd/jwker/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /workspace/jwker /jwker

CMD ["/jwker"]
